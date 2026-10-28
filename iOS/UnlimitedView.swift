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
                Image("Logo")
                    .resizable()
                    .frame(width: 72, height: 72)
                    .accessibilityHidden(true)
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
        .planPicker()
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

private extension View {
    /// The plans by length and price only, since the header already names the subscription. iOS 17 can't draw its own
    /// rows, so it shows Apple's with the products' display names.
    @ViewBuilder func planPicker() -> some View {
        if #available(iOS 18, *) {
            subscriptionStoreControlStyle(PlanPicker())
        } else {
            productDescription(.hidden)
        }
    }
}

/// "Yearly" and "Monthly" with their price, the yearly one with what it saves over paying monthly.
@available(iOS 18, *)
private struct PlanPicker: SubscriptionStoreControlStyle {
    func makeBody(configuration: Configuration) -> some View {
        let saving = Self.yearlySaving(configuration.options.map(\.subscription))
        SubscriptionPicker(configuration) { plan in
            let yearly = plan.subscriptionPeriod?.unit == .year
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(yearly ? "Yearly" : "Monthly")
                        .font(.headline)
                    HStack(spacing: 6) {
                        Text("\(plan.displayPrice) a \(yearly ? "year" : "month")")
                        if yearly, let saving {
                            Text("Save \(saving)")
                                .fontWeight(.semibold)
                                .foregroundStyle(.tint)
                        }
                    }
                    .font(.subheadline)
                }
                Spacer()
                Image(systemName: plan.isSelected ? "checkmark.circle.fill" : "circle")
                    .font(.title2)
                    .foregroundStyle(plan.isSelected ? AnyShapeStyle(.tint) : AnyShapeStyle(.tertiary))
            }
        } confirmation: { plan in
            SubscribeButton(plan)
        }
    }

    /// How much less a year costs on the yearly plan than in twelve months, rounded down so it never says too much.
    static func yearlySaving(_ plans: [Product]) -> String? {
        func price(_ unit: Product.SubscriptionPeriod.Unit) -> Decimal? {
            let plan = plans.first { $0.subscription?.subscriptionPeriod.unit == unit }
            return plan?.subscription?.subscriptionPeriod.value == 1 ? plan?.price : nil
        }
        guard let yearly = price(.year), let monthly = price(.month), monthly > 0 else { return nil }
        let saving = 1 - yearly / (12 * monthly)
        return saving >= 0.01 ? saving.formatted(.percent.precision(.fractionLength(0)).rounded(rule: .down)) : nil
    }
}
