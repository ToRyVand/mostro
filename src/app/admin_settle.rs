use crate::app::bond::{self, BondSlashReason};
use crate::app::context::AppContext;
use crate::app::dispute::close_dispute_after_user_resolution;
use crate::db::{
    claim_order_status, ensure_dispute_finalize_permission, is_assigned_solver,
    is_dispute_taken_by_admin,
};
use crate::lightning::LndConnector;
use crate::util::{enqueue_order_msg, get_order, settle_seller_hold_invoice, update_order_event};

use mostro_core::prelude::*;
use nostr_sdk::prelude::*;
use std::str::FromStr;
use tracing::error;

use super::release::do_payment;

pub async fn admin_settle_action(
    ctx: &AppContext,
    msg: Message,
    event: &UnwrappedMessage,
    my_keys: &Keys,
    ln_client: &mut LndConnector,
) -> Result<(), MostroError> {
    let pool = ctx.pool();
    // Get request id
    let request_id = msg.get_inner_message_kind().request_id;
    // Get order
    let order = get_order(&msg, pool).await?;

    match is_assigned_solver(pool, &event.identity.to_string(), order.id).await {
        Ok(false) => {
            // Check if admin has taken over the dispute
            if is_dispute_taken_by_admin(pool, order.id, &my_keys.public_key().to_string()).await? {
                return Err(MostroCantDo(
                    mostro_core::error::CantDoReason::DisputeTakenByAdmin,
                ));
            } else {
                return Err(MostroCantDo(
                    mostro_core::error::CantDoReason::IsNotYourDispute,
                ));
            }
        }
        Err(e) => {
            return Err(MostroInternalErr(ServiceError::DbAccessError(
                e.to_string(),
            )));
        }
        _ => {}
    }

    ensure_dispute_finalize_permission(
        pool,
        &event.identity.to_string(),
        &my_keys.public_key().to_string(),
        order.id,
    )
    .await?;

    // Was order cooperatively cancelled?
    if order.check_status(Status::CooperativelyCanceled).is_ok() {
        enqueue_order_msg(
            request_id,
            Some(order.id),
            Action::CooperativeCancelAccepted,
            None,
            event.identity,
            msg.get_inner_message_kind().trade_index,
        )
        .await;

        return Ok(());
    }

    if let Err(cause) = order.check_status(Status::Dispute) {
        return Err(MostroCantDo(cause));
    }

    // Phase 2: extract and validate the optional `BondResolution` payload
    // here — after the status guards above (which are non-destructive
    // early returns, so an admin retry against an already-cooperatively-
    // cancelled or out-of-dispute order still gets the prior status-
    // driven response) and before any trade-side mutation
    // (`settle_seller_hold_invoice` / `update_order_event` below). On a
    // `slash_*=true` for a side with no `Locked` bond row we return
    // `CantDo(InvalidPayload)` and the trade does not settle; the solver
    // resends a corrected directive. Absent payload ≡
    // `BondResolution { false, false }` ≡ Phase 1 behaviour (release all
    // active bonds, slash none). See `docs/ANTI_ABUSE_BOND.md` §7.3.
    let bond_resolution = bond::extract_bond_resolution(&msg);
    bond::validate_bond_resolution(pool, &order, &bond_resolution).await?;

    // Resolve the dispute initiator *before* the settle (#805, same class as
    // the fix applied to `admin_cancel`). `settle_seller_hold_invoice` is
    // irreversible: resolving the initiator afterwards meant a rejected
    // request had already moved the escrow, and the early return then also
    // skipped the `AdminSettled` fan-out and the bond resolution below.
    // The initiator itself is resolved again by the dispute close below; what
    // has to happen here is the refusal, before the escrow moves.
    match (order.seller_dispute, order.buyer_dispute) {
        (true, false) | (false, true) => {}
        (seller_dispute, buyer_dispute) => {
            // Only reachable through a corrupted row — `dispute_action`
            // gates on `Active`/`FiatSent`, so exactly one flag is set by
            // the time an order reaches `Dispute`.
            error!(
                order_id = %order.id,
                seller_dispute,
                buyer_dispute,
                "admin_settle: ambiguous dispute initiator flags; refusing before the escrow is settled"
            );
            return Err(MostroInternalErr(ServiceError::DisputeEventError));
        }
    }

    // #809: claim `Dispute → SettledHoldInvoice` before the settle, so a
    // losing concurrent handler never reaches LND. A miss means another path
    // owns the transition.
    //
    // The helper's `cashu_escrow_locked_at IS NULL` predicate excludes nothing
    // here *while* `dispatch_cashu` refuses `AdminSettle` and no locked order
    // can reach `Dispute` in the same run. Two things end that, and both need
    // a CAS of their own rather than this helper: TD-3, whose Track D §5C
    // makes a locked escrow the buyer-wins path here rather than something to
    // refuse; and a daemon restarted in Lightning mode against a database that
    // was in Cashu mode — nothing ever clears the lock
    // (`find_locked_cashu_orders` pins that as deliberate), so such an order
    // can be disputed and then never admin-settled.
    if !claim_order_status(pool, order.id, Status::Dispute, Status::SettledHoldInvoice).await? {
        tracing::warn!(
            order_id = %order.id,
            "admin_settle: the dispute → settled-hold-invoice claim matched no row; escrow untouched"
        );
        // Refused rather than `Ok`: a silent `Ok` has the gRPC surface report
        // a settle that never happened, and leaves a solver on the Nostr path
        // with no reply. The reason is the one the guard above answers for the
        // same condition — the order is no longer in `Dispute`, found a moment
        // later — so a solver that retries is told the same thing twice.
        return Err(MostroCantDo(CantDoReason::InvalidOrderStatus));
    }

    // Settle seller hold invoice
    if let Err(e) =
        settle_seller_hold_invoice(event, ln_client, Action::AdminSettled, true, &order).await
    {
        // The claim is standing and the `Dispute` guard blocks a retry, so
        // release it, only if the status is still ours. Best effort: the
        // settle's error is what the caller needs.
        if let Err(release) =
            claim_order_status(pool, order.id, Status::SettledHoldInvoice, Status::Dispute).await
        {
            error!(
                order_id = %order.id,
                "admin_settle: could not release the settle claim after a failed settle; the order \
                 stays settled-hold-invoice with its escrow unsettled: {release}"
            );
        }
        return Err(MostroInternalErr(ServiceError::LnNodeError(e.to_string())));
    }

    // Past the settle the escrow has moved and the `Dispute` guard rejects a
    // retry, so nothing below may abort the handler: an early return strands
    // every `Locked` bond and skips the buyer's payout with no path back.
    // Everything from here down is therefore best effort — the reason
    // `admin_cancel` already gives for its own notification fan-out, extended
    // here to every step that can fail after the money has moved.
    //
    // The claim already persisted the status; this only republishes the event
    // and patches its id.
    let order_updated = match update_order_event(my_keys, Status::SettledHoldInvoice, &order).await
    {
        Ok(updated) => {
            if let Err(e) = sqlx::query("UPDATE orders SET event_id = ? WHERE id = ?")
                .bind(&updated.event_id)
                .bind(updated.id)
                .execute(pool)
                .await
            {
                error!(
                    order_id = %order.id,
                    "admin_settle: could not patch the republished event id: {e}"
                );
            }
            updated
        }
        Err(e) => {
            error!(
                order_id = %order.id,
                "admin_settle: could not republish the settled order event: {e}"
            );
            // The claim wrote the status, so carry that forward: the payout
            // and the bond resolution below still need the order.
            let mut fallback = order.clone();
            fallback.status = Status::SettledHoldInvoice.to_string();
            fallback
        }
    };

    // Close the dispute row and republish its event through the shared
    // helper `release_action` and `cancel.rs` already use: it logs a failed
    // update and steps over it, and publishes only when the row actually
    // moved, so relays never advertise a settlement the database does not
    // carry.
    close_dispute_after_user_resolution(
        ctx,
        &order_updated,
        DisputeStatus::Settled,
        my_keys,
        "admin settle",
    )
    .await;

    // Send message to event creator
    enqueue_order_msg(
        request_id,
        Some(order_updated.id),
        Action::AdminSettled,
        None,
        event.sender,
        msg.get_inner_message_kind().trade_index,
    )
    .await;

    // Send message to seller and buyer. An unparseable pubkey used to abort
    // the handler here — past the settle, so it stranded the bonds and the
    // payout below over a notification nobody could receive anyway.
    for (role, pubkey) in [
        ("seller", &order_updated.seller_pubkey),
        ("buyer", &order_updated.buyer_pubkey),
    ] {
        match pubkey.as_deref().map(PublicKey::from_str) {
            Some(Ok(destination)) => {
                enqueue_order_msg(
                    None,
                    Some(order_updated.id),
                    Action::AdminSettled,
                    None,
                    destination,
                    msg.get_inner_message_kind().trade_index,
                )
                .await
            }
            Some(Err(_)) => error!(
                order_id = %order_updated.id,
                "admin_settle: unparseable {role} pubkey; skipping the settlement notice"
            ),
            None => error!(
                order_id = %order_updated.id,
                "admin_settle: no {role} pubkey on a settled order; no settlement notice sent"
            ),
        }
    }
    // Phase 2: apply the solver's `BondResolution` (release-by-default
    // when absent, otherwise slash the flagged sides). Slashed bonds
    // have their hold invoices settled immediately; the recipient
    // payout (asking the winning counterparty for a bolt11,
    // `send_payment`, retries, forfeiture on the long-stop window) is
    // still Phase 3's job.
    // #768: notify each slashed party with a best-effort `BondSlashed`
    // forfeiture notice, mirroring the timeout-slash path. Only confirmed
    // slashes are returned, so a dropped settle never produces an untruthful
    // notice and an idempotent retry never re-notifies.
    match bond::apply_bond_resolution(
        pool,
        ln_client,
        &order_updated,
        &bond_resolution,
        BondSlashReason::LostDispute,
    )
    .await
    {
        Ok(slashed_rows) => {
            for slashed in &slashed_rows {
                bond::notify_bond_slashed(&order_updated, slashed).await;
            }
        }
        Err(e) => {
            tracing::warn!(
                order_id = %order_updated.id,
                "admin_settle: bond resolution apply failed: {}", e
            );
        }
    }

    // Phase 6: a dispute resolution ends the range (no remainder is
    // republished), so resolve the maker bond at close — settle the parent
    // HTLC once and refund the unslashed remainder if any slice was slashed,
    // otherwise release. A no-op for non-range maker bonds (already handled
    // inline by `apply_bond_resolution`) and for orders with no maker bond.
    if let Err(e) = bond::resolve_range_maker_bond_at_close(pool, ln_client, &order_updated).await {
        tracing::warn!(
            order_id = %order_updated.id,
            "admin_settle: maker bond close failed: {}", e
        );
    }

    let _ = do_payment(ctx, order_updated, request_id).await;

    Ok(())
}

#[cfg(test)]
mod handler_tests {
    use super::*;
    use crate::app::context::test_utils::{test_settings, TestContextBuilder};
    use crate::lightning::LndConnector;
    use sqlx::SqlitePool;
    use std::sync::Arc;

    async fn setup_pool() -> Arc<SqlitePool> {
        let pool = Arc::new(SqlitePool::connect("sqlite::memory:").await.unwrap());
        sqlx::migrate!("./migrations")
            .run(pool.as_ref())
            .await
            .unwrap();
        pool
    }

    fn build_ctx(pool: Arc<SqlitePool>) -> AppContext {
        let _ = crate::config::MOSTRO_CONFIG.set(test_settings());
        TestContextBuilder::new()
            .with_pool(pool)
            .with_settings(test_settings())
            .build()
    }

    /// Real `LndConnector` against a dead endpoint: `connect` is lazy so it
    /// always builds, but every RPC fails fast. Handlers take `&mut
    /// LndConnector` by value, so tests must supply one even for paths that
    /// return before any LND call.
    async fn dead_lnd() -> LndConnector {
        let dir = std::env::temp_dir().join(format!("mostro-test-lnd-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("tls.cert");
        let mac = dir.join("admin.macaroon");
        std::fs::write(&cert, b"").unwrap();
        std::fs::write(&mac, [1u8, 2u8]).unwrap();
        let client = fedimint_tonic_lnd::connect(
            "https://127.0.0.1:1".to_string(),
            cert.to_str().unwrap().to_string(),
            mac.to_str().unwrap().to_string(),
        )
        .await
        .expect("lazy connect never dials");
        LndConnector { client }
    }

    /// `event.identity` is the seal signer the admin-gating checks against;
    /// `sender` is the trade key.
    fn admin_event(identity: PublicKey) -> UnwrappedMessage {
        UnwrappedMessage {
            message: Message::new_order(None, Some(1), None, Action::AdminSettle, None),
            signature: None,
            sender: Keys::generate().public_key(),
            identity,
            created_at: Timestamp::now(),
        }
    }

    fn dispute_order(seller: PublicKey, buyer: PublicKey) -> Order {
        Order {
            id: uuid::Uuid::new_v4(),
            status: Status::Dispute.to_string(),
            kind: mostro_core::order::Kind::Sell.to_string(),
            fiat_code: "USD".to_string(),
            creator_pubkey: seller.to_string(),
            seller_pubkey: Some(seller.to_string()),
            buyer_pubkey: Some(buyer.to_string()),
            amount: 21_000,
            fee: 210,
            ..Default::default()
        }
    }

    async fn assign_solver(pool: &SqlitePool, order_id: uuid::Uuid, solver: &PublicKey) {
        // `Dispute::new` always starts in `Initiated`; the admin-takeover
        // detection queries for `in-progress`, so set it explicitly.
        let mut dispute = Dispute::new(order_id, Status::Dispute.to_string());
        dispute.status = DisputeStatus::InProgress.to_string();
        dispute.solver_pubkey = Some(solver.to_string());
        dispute.create(pool).await.unwrap();
    }

    fn settle_msg(order_id: uuid::Uuid) -> Message {
        Message::new_order(Some(order_id), Some(1), None, Action::AdminSettle, None)
    }

    async fn queued_actions_for(destination: PublicKey) -> Vec<Action> {
        crate::config::MESSAGE_QUEUES
            .queue_order_msg
            .read()
            .await
            .iter()
            .filter(|(_, pk)| *pk == destination)
            .map(|(m, _)| m.get_inner_message_kind().action.clone())
            .collect()
    }

    #[tokio::test]
    async fn fails_when_order_missing() {
        let pool = setup_pool().await;
        let ctx = build_ctx(pool);
        let mut ln = dead_lnd().await;
        let admin = Keys::generate();

        let result = admin_settle_action(
            &ctx,
            settle_msg(uuid::Uuid::new_v4()),
            &admin_event(admin.public_key()),
            &admin,
            &mut ln,
        )
        .await;

        assert!(matches!(result, Err(MostroCantDo(CantDoReason::NotFound))));
    }

    #[tokio::test]
    async fn rejects_caller_not_assigned_and_no_admin_takeover() {
        let pool = setup_pool().await;
        let ctx = build_ctx(pool.clone());
        let mut ln = dead_lnd().await;
        let admin = Keys::generate();
        let seller = Keys::generate().public_key();
        let buyer = Keys::generate().public_key();

        let order = dispute_order(seller, buyer)
            .create(ctx.pool())
            .await
            .unwrap();

        // No dispute row → not assigned and not taken by admin.
        let result = admin_settle_action(
            &ctx,
            settle_msg(order.id),
            &admin_event(Keys::generate().public_key()),
            &admin,
            &mut ln,
        )
        .await;

        assert!(matches!(
            result,
            Err(MostroCantDo(CantDoReason::IsNotYourDispute))
        ));
    }

    #[tokio::test]
    async fn reports_admin_takeover_when_dispute_in_progress_with_admin() {
        let pool = setup_pool().await;
        let ctx = build_ctx(pool.clone());
        let mut ln = dead_lnd().await;
        let admin = Keys::generate();
        let seller = Keys::generate().public_key();
        let buyer = Keys::generate().public_key();

        let order = dispute_order(seller, buyer)
            .create(ctx.pool())
            .await
            .unwrap();
        // Dispute is in-progress and taken over by the admin (mostro) key.
        assign_solver(ctx.pool(), order.id, &admin.public_key()).await;

        // Caller is some unrelated solver key, not assigned.
        let result = admin_settle_action(
            &ctx,
            settle_msg(order.id),
            &admin_event(Keys::generate().public_key()),
            &admin,
            &mut ln,
        )
        .await;

        assert!(matches!(
            result,
            Err(MostroCantDo(CantDoReason::DisputeTakenByAdmin))
        ));
    }

    /// Caller is the assigned solver but is neither the admin key nor a
    /// read-write solver user row → `ensure_dispute_finalize_permission`
    /// rejects with `NotAuthorized`.
    #[tokio::test]
    async fn rejects_assigned_solver_without_write_permission() {
        let pool = setup_pool().await;
        let ctx = build_ctx(pool.clone());
        let mut ln = dead_lnd().await;
        let admin = Keys::generate();
        let solver = Keys::generate();
        let seller = Keys::generate().public_key();
        let buyer = Keys::generate().public_key();

        let order = dispute_order(seller, buyer)
            .create(ctx.pool())
            .await
            .unwrap();
        assign_solver(ctx.pool(), order.id, &solver.public_key()).await;

        let result = admin_settle_action(
            &ctx,
            settle_msg(order.id),
            &admin_event(solver.public_key()),
            &admin,
            &mut ln,
        )
        .await;

        assert!(matches!(
            result,
            Err(MostroCantDo(CantDoReason::NotAuthorized))
        ));
    }

    /// A cooperatively-cancelled order short-circuits: the admin (whose
    /// identity == the mostro key, so the finalize-permission admin
    /// shortcut applies) is acknowledged and the handler returns `Ok`
    /// before any settle.
    #[tokio::test]
    async fn cooperatively_cancelled_order_acknowledges_admin() {
        let pool = setup_pool().await;
        let ctx = build_ctx(pool.clone());
        let mut ln = dead_lnd().await;
        let admin = Keys::generate();
        let seller = Keys::generate().public_key();
        let buyer = Keys::generate().public_key();

        let mut order = dispute_order(seller, buyer);
        order.status = Status::CooperativelyCanceled.to_string();
        let order = order.create(ctx.pool()).await.unwrap();
        // Admin identity is the assigned solver → finalize permission via
        // the caller==admin shortcut.
        assign_solver(ctx.pool(), order.id, &admin.public_key()).await;

        let result = admin_settle_action(
            &ctx,
            settle_msg(order.id),
            &admin_event(admin.public_key()),
            &admin,
            &mut ln,
        )
        .await;

        assert!(
            result.is_ok(),
            "coop-cancel must ack and return Ok: {result:?}"
        );
        assert!(queued_actions_for(admin.public_key())
            .await
            .contains(&Action::CooperativeCancelAccepted));
    }

    /// An order that is neither cooperatively-cancelled nor in dispute is
    /// rejected by the status guard.
    #[tokio::test]
    async fn rejects_order_not_in_dispute() {
        let pool = setup_pool().await;
        let ctx = build_ctx(pool.clone());
        let mut ln = dead_lnd().await;
        let admin = Keys::generate();
        let seller = Keys::generate().public_key();
        let buyer = Keys::generate().public_key();

        let mut order = dispute_order(seller, buyer);
        order.status = Status::Active.to_string();
        let order = order.create(ctx.pool()).await.unwrap();
        assign_solver(ctx.pool(), order.id, &admin.public_key()).await;

        let result = admin_settle_action(
            &ctx,
            settle_msg(order.id),
            &admin_event(admin.public_key()),
            &admin,
            &mut ln,
        )
        .await;

        assert!(matches!(
            result,
            Err(MostroCantDo(CantDoReason::InvalidOrderStatus))
        ));
    }

    /// Same invariant as `admin_cancel` (#805): with the initiator flags
    /// unset, the request must be rejected *before* the irreversible
    /// `settle_seller_hold_invoice`. Pre-fix the initiator was resolved
    /// after the settle, so this order reached the settle seam and returned
    /// `LnNodeError` — the escrow moved on a request that was then rejected,
    /// skipping the `AdminSettled` fan-out and the bond resolution.
    #[tokio::test]
    async fn dispute_without_initiator_flag_errors_before_settling() {
        let pool = setup_pool().await;
        let ctx = build_ctx(pool.clone());
        let mut ln = dead_lnd().await;
        let admin = Keys::generate();
        let seller = Keys::generate().public_key();
        let buyer = Keys::generate().public_key();

        // Neither side flagged as initiator; `preimage` is left as the
        // dispute-order default so the settle seam is genuinely reachable.
        let order = dispute_order(seller, buyer)
            .create(ctx.pool())
            .await
            .unwrap();
        assign_solver(ctx.pool(), order.id, &admin.public_key()).await;

        let result = admin_settle_action(
            &ctx,
            settle_msg(order.id),
            &admin_event(admin.public_key()),
            &admin,
            &mut ln,
        )
        .await;

        assert!(
            matches!(
                result,
                Err(MostroInternalErr(ServiceError::DisputeEventError))
            ),
            "expected the initiator check to reject before the settle, got {result:?}"
        );

        let stored = Order::by_id(ctx.pool(), order.id).await.unwrap().unwrap();
        assert_eq!(stored.status, Status::Dispute.to_string());
    }

    /// A genuine dispute settle reaches `settle_seller_hold_invoice`, which
    /// short-circuits on the missing preimage before any LND call and is
    /// mapped to `LnNodeError`. The LND settle + `do_payment` tail beyond
    /// this seam requires a live node and is covered by integration tests.
    #[tokio::test]
    async fn dispute_order_reaches_settle_seam() {
        let pool = setup_pool().await;
        let ctx = build_ctx(pool.clone());
        let mut ln = dead_lnd().await;
        let admin = Keys::generate();
        let seller = Keys::generate().public_key();
        let buyer = Keys::generate().public_key();

        let mut order = dispute_order(seller, buyer);
        order.seller_dispute = true;
        order.preimage = None; // settle short-circuits with InvalidInvoice
        let order = order.create(ctx.pool()).await.unwrap();
        assign_solver(ctx.pool(), order.id, &admin.public_key()).await;

        let result = admin_settle_action(
            &ctx,
            settle_msg(order.id),
            &admin_event(admin.public_key()),
            &admin,
            &mut ln,
        )
        .await;

        assert!(matches!(
            result,
            Err(MostroInternalErr(ServiceError::LnNodeError(_)))
        ));
    }

    /// #809: losing the claim has to stop the handler *before* the settle, and
    /// say so — a silent `Ok` reports a settle that never happened. The
    /// interleaving is not deterministically testable, so the miss is injected
    /// with a `BEFORE UPDATE … RAISE(IGNORE)` trigger on the claim's own
    /// write, which leaves exactly what losing the race leaves:
    /// `rows_affected() == 0`. The `preimage` stays `None`, so a settle that
    /// was reached would surface as `LnNodeError`
    /// (`dispute_order_reaches_settle_seam`) instead of this refusal.
    #[tokio::test]
    async fn a_lost_claim_refuses_before_the_settle() {
        let pool = setup_pool().await;
        let ctx = build_ctx(pool.clone());
        let mut ln = dead_lnd().await;
        let admin = Keys::generate();
        let seller = Keys::generate().public_key();
        let buyer = Keys::generate().public_key();

        let mut order = dispute_order(seller, buyer);
        order.seller_dispute = true;
        order.preimage = None;
        let order = order.create(ctx.pool()).await.unwrap();
        assign_solver(ctx.pool(), order.id, &admin.public_key()).await;
        sqlx::query(
            "CREATE TRIGGER lose_the_claim BEFORE UPDATE ON orders \
             WHEN new.status = 'settled-hold-invoice' BEGIN SELECT RAISE(IGNORE); END",
        )
        .execute(ctx.pool())
        .await
        .unwrap();

        let result = admin_settle_action(
            &ctx,
            settle_msg(order.id),
            &admin_event(admin.public_key()),
            &admin,
            &mut ln,
        )
        .await;

        assert!(
            matches!(result, Err(MostroCantDo(CantDoReason::InvalidOrderStatus))),
            "a lost claim must refuse before the settle, got {result:?}"
        );
        let stored = Order::by_id(ctx.pool(), order.id).await.unwrap().unwrap();
        assert_eq!(
            stored.status,
            Status::Dispute.to_string(),
            "the order must be left to whichever path owns the transition"
        );
    }

    /// The two transitions `admin_settle_action` drives through
    /// `claim_order_status`: the claim, and its release on a failed settle.
    async fn claim_settle(pool: &SqlitePool, order_id: uuid::Uuid) -> bool {
        claim_order_status(pool, order_id, Status::Dispute, Status::SettledHoldInvoice)
            .await
            .unwrap()
    }

    async fn release_settle(pool: &SqlitePool, order_id: uuid::Uuid) -> bool {
        claim_order_status(pool, order_id, Status::SettledHoldInvoice, Status::Dispute)
            .await
            .unwrap()
    }

    /// #809: exactly one caller can win `Dispute → SettledHoldInvoice`. The
    /// race itself is not deterministically testable; this exclusivity is.
    #[tokio::test]
    async fn settle_claim_admits_exactly_one_winner() {
        let pool = setup_pool().await;
        let ctx = build_ctx(pool.clone());
        let seller = Keys::generate().public_key();
        let buyer = Keys::generate().public_key();

        let order = dispute_order(seller, buyer)
            .create(ctx.pool())
            .await
            .unwrap();

        assert!(
            claim_settle(ctx.pool(), order.id).await,
            "the first claim against a disputed order must win it"
        );
        assert!(
            !claim_settle(ctx.pool(), order.id).await,
            "the second claim must miss — the row has left dispute"
        );

        let stored = Order::by_id(ctx.pool(), order.id).await.unwrap().unwrap();
        assert_eq!(stored.status, Status::SettledHoldInvoice.to_string());
    }

    /// The release is conditional on the status this handler wrote, so a
    /// release racing a later transition must not drag the order backwards.
    #[tokio::test]
    async fn releasing_a_settle_claim_leaves_other_statuses_alone() {
        let pool = setup_pool().await;
        let ctx = build_ctx(pool.clone());
        let seller = Keys::generate().public_key();
        let buyer = Keys::generate().public_key();

        let mut order = dispute_order(seller, buyer);
        order.status = Status::CanceledByAdmin.to_string();
        let order = order.create(ctx.pool()).await.unwrap();

        assert!(
            !release_settle(ctx.pool(), order.id).await,
            "a release against a status this handler does not own must miss"
        );
        let stored = Order::by_id(ctx.pool(), order.id).await.unwrap().unwrap();
        assert_eq!(stored.status, Status::CanceledByAdmin.to_string());
    }

    /// #809: a failed settle must surface and hand the order back to
    /// `Dispute`; the `Dispute` guard would otherwise block any retry.
    #[tokio::test]
    async fn failed_settle_releases_the_claim() {
        let pool = setup_pool().await;
        let ctx = build_ctx(pool.clone());
        let mut ln = dead_lnd().await;
        let admin = Keys::generate();
        let seller = Keys::generate().public_key();
        let buyer = Keys::generate().public_key();

        let mut order = dispute_order(seller, buyer);
        order.seller_dispute = true;
        order.preimage = None; // settle short-circuits with InvalidInvoice
        let order = order.create(ctx.pool()).await.unwrap();
        assign_solver(ctx.pool(), order.id, &admin.public_key()).await;

        let result = admin_settle_action(
            &ctx,
            settle_msg(order.id),
            &admin_event(admin.public_key()),
            &admin,
            &mut ln,
        )
        .await;

        assert!(
            matches!(result, Err(MostroInternalErr(ServiceError::LnNodeError(_)))),
            "the failed settle must surface, got {result:?}"
        );

        let stored = Order::by_id(ctx.pool(), order.id).await.unwrap().unwrap();
        assert_eq!(
            stored.status,
            Status::Dispute.to_string(),
            "a failed settle must release the claim so the solver can retry"
        );
    }
}

#[cfg(test)]
mod tests {
    use mostro_core::error::CantDoReason;

    /// Test that our error handling logic correctly identifies admin takeover vs regular disputes
    /// This tests the core business logic of issue #302 without complex database setup
    #[test]
    fn test_dispute_error_types() {
        // Test that we have the correct error types available
        // This ensures our mostro-core dependency includes the new DisputeTakenByAdmin variant

        // Original error for regular dispute issues
        let regular_error = CantDoReason::IsNotYourDispute;
        assert_eq!(format!("{:?}", regular_error), "IsNotYourDispute");

        // New error for admin takeover scenarios
        let admin_error = CantDoReason::DisputeTakenByAdmin;
        assert_eq!(format!("{:?}", admin_error), "DisputeTakenByAdmin");

        // New error for authenticated callers lacking enough permissions
        let unauthorized_error = CantDoReason::NotAuthorized;
        assert_eq!(format!("{:?}", unauthorized_error), "NotAuthorized");

        // Verify they are different error types
        assert_ne!(regular_error, admin_error);
        assert_ne!(admin_error, unauthorized_error);
    }
}
