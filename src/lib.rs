#![forbid(unsafe_code)]

//! The transport authorize technology — a technology of `xmip-core-authorize`.
//!
//! One policy at the transport layer: rules on the transport identity — its
//! mechanism, its class, its address (ADR-0050 section 5). The identity it
//! judges is the accountable one, the transport identity, because that is who
//! opened the connection (ADR-0019 clause 7). A [`TransportRule`] names the
//! mechanisms, classes and networks it applies to and, where the rule is
//! about what a connection may carry, the Contracts; every list it leaves
//! empty means any. The rules are consulted in order and the first that
//! applies decides: a plain-text mechanism may not carry a given Contract, a
//! shared secret from outside the partner network may not post here, a
//! mutually authenticated connection may.
//!
//! **The address.** Where the mechanism is `ip` the value is the address.
//! Otherwise it is read from the evidence the first gate recorded under
//! [`context::property::PEER_ADDRESS`] — the name identification writes it under, which
//! this read as `address` until 2026-09-22 and so never met — the one
//! evidence name this policy branches on; a rule that
//! names networks and an identity with no readable address do not meet. A
//! rule that names Contracts and an attempt with none do not meet either.
//! An attempt no rule applies to is no opinion.

use authorize::{Attempt, Authorizer, Decision};
use context::property::PEER_ADDRESS;
use context::{AuthenticatedIdentity, IdentityFacts};
use net::Network;
use std::net::IpAddr;
use xcore::{IdentityClass, Layer};

/// The manifest leaf, and the name a denial carries.
pub const NAME: &str = "transport";

/// What a rule concludes where it applies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    Allow,
    Deny,
}

/// One rule: where it applies, and what it concludes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportRule {
    name: String,
    effect: Effect,
    mechanisms: Vec<String>,
    classes: Vec<IdentityClass>,
    networks: Vec<Network>,
    contracts: Vec<String>,
}

impl TransportRule {
    /// A rule that allows where it applies, named for the denial log.
    #[must_use]
    pub fn allow(name: impl Into<String>) -> Self {
        Self::new(name, Effect::Allow)
    }

    /// A rule that denies where it applies.
    #[must_use]
    pub fn deny(name: impl Into<String>) -> Self {
        Self::new(name, Effect::Deny)
    }

    fn new(name: impl Into<String>, effect: Effect) -> Self {
        Self {
            name: name.into(),
            effect,
            mechanisms: Vec::new(),
            classes: Vec::new(),
            networks: Vec::new(),
            contracts: Vec::new(),
        }
    }

    /// Applies to this mechanism, by the name the catalog declares.
    #[must_use]
    pub fn mechanism(mut self, name: impl Into<String>) -> Self {
        self.mechanisms.push(name.into());
        self
    }

    /// Applies to this identity class.
    #[must_use]
    pub fn class(mut self, class: IdentityClass) -> Self {
        self.classes.push(class);
        self
    }

    /// Applies where the peer address is inside this network.
    #[must_use]
    pub fn network(mut self, network: Network) -> Self {
        self.networks.push(network);
        self
    }

    /// Applies where the attempt carries this Contract.
    #[must_use]
    pub fn contract(mut self, contract: impl Into<String>) -> Self {
        self.contracts.push(contract.into());
        self
    }

    fn applies(&self, identity: &AuthenticatedIdentity, attempt: &Attempt) -> bool {
        let mechanism = self.mechanisms.is_empty()
            || self
                .mechanisms
                .iter()
                .any(|m| m == identity.mechanism.name());
        let class = self.classes.is_empty() || self.classes.contains(&identity.class());
        let network = self.networks.is_empty()
            || address_of(identity).is_some_and(|address| {
                self.networks
                    .iter()
                    .any(|network| network.contains(address))
            });
        let contract = self.contracts.is_empty()
            || attempt
                .contract
                .as_ref()
                .is_some_and(|contract| self.contracts.contains(contract));

        mechanism && class && network && contract
    }
}

/// The peer address, where the identity has one to read.
#[must_use]
pub fn address_of(identity: &AuthenticatedIdentity) -> Option<IpAddr> {
    let text = if identity.mechanism.name() == "ip" {
        identity.value.as_str()
    } else {
        identity
            .evidence
            .iter()
            .find(|(name, _)| name == PEER_ADDRESS)
            .map(|(_, value)| value.as_str())?
    };

    net::address::parse(text).ok()
}

/// The rules, in the order they are consulted.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TransportPolicy {
    rules: Vec<TransportRule>,
}

impl TransportPolicy {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule after those already there.
    #[must_use]
    pub fn rule(mut self, rule: TransportRule) -> Self {
        self.rules.push(rule);
        self
    }
}

impl Authorizer for TransportPolicy {
    fn name(&self) -> &str {
        NAME
    }

    fn layer(&self) -> Layer {
        Layer::Transport
    }

    fn decide(&self, identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision> {
        let accountable = identity.accountable();
        let rule = self
            .rules
            .iter()
            .find(|rule| rule.applies(accountable, attempt))?;

        match rule.effect {
            Effect::Allow => Some(Decision::Allowed),
            Effect::Deny => {
                let address = address_of(accountable)
                    .map(|address| format!(" from {address}"))
                    .unwrap_or_default();
                let contract = attempt
                    .contract
                    .as_ref()
                    .map(|contract| format!(" carrying {contract}"))
                    .unwrap_or_default();

                Some(Decision::denied(
                    NAME,
                    format!(
                        "rule '{}' refuses {}={} ({}){address}{contract}",
                        rule.name,
                        accountable.mechanism.name(),
                        accountable.value,
                        accountable.class()
                    ),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authorize::Action;
    use context::{Alignment, Verified};
    use xcore::{Established, Mechanism, mechanism};

    fn facts(mechanism: Mechanism, value: &str, address: Option<&str>) -> IdentityFacts {
        let identity =
            AuthenticatedIdentity::new(mechanism, value, Established::Passed, Verified::Proven);
        let identity = match address {
            Some(address) => identity.with_evidence(PEER_ADDRESS, address),
            None => identity,
        };

        IdentityFacts::evaluate(Alignment::None, identity, None)
    }

    fn network(text: &str) -> Network {
        Network::parse(text).expect("a network")
    }

    fn policy() -> TransportPolicy {
        TransportPolicy::new()
            .rule(
                TransportRule::deny("no-plain-text-orders")
                    .class(IdentityClass::SharedSecret)
                    .contract("Orders"),
            )
            .rule(TransportRule::deny("partner-network-only").mechanism("basic"))
            .rule(
                TransportRule::allow("partner-network")
                    .mechanism("basic")
                    .network(network("10.20.0.0/16")),
            )
            .rule(TransportRule::allow("mutually-authenticated").mechanism("mutual-tls"))
    }

    #[test]
    fn a_mutually_authenticated_connection_is_allowed_by_the_rule_that_names_it() {
        let decision = policy().decide(
            &facts(mechanism::mutual_tls(), "CN=partner-x.example", None),
            &Attempt::new(Action::Receive, "partner-x"),
        );

        assert_eq!(decision, Some(Decision::Allowed));
        assert_eq!(policy().name(), "transport");
        assert_eq!(policy().layer(), Layer::Transport);
    }

    #[test]
    fn a_shared_secret_may_not_carry_the_contract_the_rule_names() {
        let decision = policy()
            .decide(
                &facts(mechanism::basic(), "alice", Some("10.20.3.4")),
                &Attempt::new(Action::Receive, "partner-x").on_contract("Orders"),
            )
            .expect("an opinion");

        assert_eq!(
            decision.to_string(),
            "denied by transport: rule 'no-plain-text-orders' refuses basic=alice \
             (sharedSecret) from 10.20.3.4 carrying Orders"
        );
    }

    #[test]
    fn an_identity_no_rule_applies_to_is_no_opinion() {
        let decision = policy().decide(
            &facts(mechanism::anonymous(), "", None),
            &Attempt::new(Action::Receive, "partner-x"),
        );

        assert_eq!(decision, None);
    }

    #[test]
    fn the_first_rule_that_applies_decides_and_an_address_is_read_from_ip_or_evidence() {
        // The deny on 'basic' comes before the allow on the partner network,
        // so the order is the policy: the network rule never gets a say.
        let inside = facts(mechanism::basic(), "alice", Some("10.20.3.4"));
        let denied = policy()
            .decide(&inside, &Attempt::new(Action::Receive, "partner-x"))
            .expect("an opinion");
        assert!(
            denied.to_string().contains("'partner-network-only'"),
            "got {denied}"
        );

        // Reordered, the network rule applies inside the partner network and
        // not outside it — where the identity is the address, or carries it.
        let reordered = TransportPolicy::new()
            .rule(
                TransportRule::allow("partner-network")
                    .mechanism("basic")
                    .mechanism("ip")
                    .network(network("10.20.0.0/16")),
            )
            .rule(TransportRule::deny("elsewhere"));
        let attempt = Attempt::new(Action::Receive, "partner-x");

        assert_eq!(reordered.decide(&inside, &attempt), Some(Decision::Allowed));
        assert_eq!(
            reordered.decide(&facts(mechanism::ip(), "10.20.9.9", None), &attempt),
            Some(Decision::Allowed)
        );
        assert_eq!(
            reordered
                .decide(&facts(mechanism::ip(), "10.21.0.1", None), &attempt)
                .expect("an opinion")
                .to_string(),
            "denied by transport: rule 'elsewhere' refuses ip=10.21.0.1 (sharedSecret) \
             from 10.21.0.1"
        );
        assert_eq!(
            address_of(&facts(mechanism::basic(), "alice", None).transport),
            None,
            "no evidence, no address"
        );
    }

    #[test]
    fn a_peer_identified_by_name_is_read_where_identification_wrote_it() {
        let named = facts(
            mechanism::dns(),
            "partner-x.example",
            Some("192.0.2.10:4711"),
        );

        assert_eq!(
            address_of(&named.transport),
            Some("192.0.2.10".parse().expect("an address")),
            "under peer.address, and with its port"
        );
    }
}
