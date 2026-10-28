import AppCore
import StoreKit
import SwiftUI

/// Why the app offers the subscription (`PhoneModel.offer`, Settings).
struct UnlimitedOffer: Identifiable {
    enum Reason { case daily, computers, asked }

    let id = UUID()
    var reason: Reason
    /// A pairing that goes ahead once you subscribe.
    var invite: PairingInvite?
}

/// The subscription, on Apple's own subscription screen: prices, Subscribe, Restore and the terms.
struct UnlimitedView: View {
    @EnvironmentObject private var model: PhoneModel
    @ObservedObject private var store = Store.shared
    @Environment(\.dismiss) private var dismiss
    let offer: UnlimitedOffer

    var body: some View {
        SubscriptionStoreView(productIDs: Store.productIDs) {
            VStack(spacing: 12) {
                Image(systemName: Biometry.symbol)
                    .font(.system(size: 48))
                    .foregroundStyle(.tint)
                Text("\(Brand.name) Unlimited")
                    .font(.title.weight(.bold))
                Text(headline)
                Text("\(store.freeSummary) Computers on a relay you host yourself have no limits.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            .multilineTextAlignment(.center)
            // The store view squeezes its header on a page of its own (from Settings), cutting off the last line.
            .fixedSize(horizontal: false, vertical: true)
            .padding()
        }
        .storeButton(.visible, for: .restorePurchases)
        .storeButton(.visible, for: .policies)
        // Settings shows it as a page of its own, with a back button.
        .storeButton(offer.reason == .asked ? .hidden : .visible, for: .cancellation)
        .subscriptionStorePolicyDestination(url: Store.terms, for: .termsOfService)
        .subscriptionStorePolicyDestination(url: Brand.privacyPolicy, for: .privacyPolicy)
        .onInAppPurchaseCompletion { _, result in
            if case .success(.success(.verified(let transaction))) = result { await transaction.finish() }
            await store.refresh()
        }
        // Bought or restored.
        .onChange(of: store.isUnlimited) { _, unlimited in
            guard unlimited else { return }
            dismiss()
            if let invite = offer.invite { Task { await model.pair(invite) } }
        }
        .onDisappear { Task { await store.refresh() } }
    }

    private var headline: String {
        switch offer.reason {
        case .daily:
            "You've used today's free unlocks and approvals. They start again at midnight; until then, your computers ask for the password as usual."
        case .computers:
            "To use more than \(Store.computers(store.limits.computers ?? 0)) with \(Brand.name), get Unlimited."
        case .asked:
            "Unlock and approve as often as you like, on as many computers as you like."
        }
    }
}
