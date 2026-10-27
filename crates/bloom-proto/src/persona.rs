//! Owner-reviewed onboarding suggestions. These types never confer signing authority.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaPreset {
    #[default]
    #[serde(alias = "institutional")]
    Custodian,
    Trader,
    Degen,
}

impl PersonaPreset {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Custodian => "custodian",
            Self::Trader => "trader",
            Self::Degen => "degen",
        }
    }
}

impl std::str::FromStr for PersonaPreset {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "institutional" | "custodian" => Ok(Self::Custodian),
            "trader" => Ok(Self::Trader),
            "degen" => Ok(Self::Degen),
            _ => Err("persona must be institutional, trader or degen".into()),
        }
    }
}

/// Saved suggestions, never signing authority. Exact deployment identities come
/// from the reviewed token catalog; symbols alone cannot authorize a token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaConfig {
    pub schema_version: u32,
    pub preset: PersonaPreset,
    pub window_secs: u64,
}
impl Default for PersonaConfig {
    fn default() -> Self {
        Self::suggested(PersonaPreset::Custodian)
    }
}
impl PersonaConfig {
    pub fn suggested(preset: PersonaPreset) -> Self {
        Self {
            schema_version: 2,
            preset,
            window_secs: match preset {
                PersonaPreset::Custodian => 0,
                PersonaPreset::Trader => 86400,
                PersonaPreset::Degen => 604800,
            },
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 2 || self.window_secs != Self::suggested(self.preset).window_secs
        {
            return Err(
                "unsupported persona token allowance configuration; choose a persona again".into(),
            );
        }
        Ok(())
    }
    /// Fixed token quantities, not USD equivalents. Each token is independent.
    pub fn token_amounts(&self, symbol: &str) -> Option<(&'static str, &'static str)> {
        let (action, total) = match symbol {
            "USDC" | "USDT" | "DAI" | "USDS" | "pUSD" | "EURC" | "GHO" | "crvUSD" => {
                (("100", "1000"), ("1000", "10000"))
            }
            "WETH" => (("0.025", "0.25"), ("0.25", "2.5")),
            "wstETH" | "rETH" | "weETH" => (("0.02", "0.2"), ("0.2", "2")),
            "WBTC" | "cbBTC" | "tBTC" => (("0.001", "0.01"), ("0.01", "0.1")),
            "WBNB" => (("0.1", "1"), ("1", "10")),
            "WAVAX" | "WHYPE" => (("2", "20"), ("20", "200")),
            "LINK" => (("5", "50"), ("50", "500")),
            "AAVE" => (("0.25", "2.5"), ("2.5", "25")),
            "UNI" => (("10", "100"), ("100", "1000")),
            "ARB" | "OP" => (("100", "1000"), ("1000", "10000")),
            _ => return None,
        };
        match self.preset {
            PersonaPreset::Custodian => None,
            PersonaPreset::Trader => Some(action),
            PersonaPreset::Degen => Some(total),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_are_recurring_token_presets() {
        let trader = PersonaConfig::suggested(PersonaPreset::Trader);
        let degen = PersonaConfig::suggested(PersonaPreset::Degen);
        assert_eq!(trader.window_secs, 86400);
        assert_eq!(degen.window_secs, 604800);
        assert_eq!(trader.token_amounts("WETH"), Some(("0.025", "0.25")));
        assert_eq!(degen.token_amounts("pUSD"), Some(("1000", "10000")));
        assert!(PersonaConfig::default().token_amounts("USDC").is_none());
        assert!(trader.token_amounts("unknown").is_none());
        for preset in [
            PersonaPreset::Custodian,
            PersonaPreset::Trader,
            PersonaPreset::Degen,
        ] {
            PersonaConfig::suggested(preset).validate().unwrap();
        }
    }
}
