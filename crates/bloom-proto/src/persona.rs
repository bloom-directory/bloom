//! Owner-reviewed onboarding suggestions. These types never confer signing authority.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaPreset {
    #[default]
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
            "custodian" => Ok(Self::Custodian),
            "trader" => Ok(Self::Trader),
            "degen" => Ok(Self::Degen),
            _ => Err("persona must be custodian, trader or degen".into()),
        }
    }
}

/// Saved suggestions for a future reviewed session, independently of Petal setup.
/// Dollars are integer microdollars. Saving this record does not activate a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaConfig {
    pub schema_version: u32,
    pub preset: PersonaPreset,
    pub per_action_usd_micros: u64,
    pub daily_usd_micros: u64,
    pub session_duration_secs: u64,
}

impl Default for PersonaConfig {
    fn default() -> Self {
        Self::suggested(PersonaPreset::Custodian)
    }
}

impl PersonaConfig {
    pub fn suggested(preset: PersonaPreset) -> Self {
        let (per_action_usd_micros, daily_usd_micros, session_duration_secs) = match preset {
            PersonaPreset::Custodian => (0, 0, 0),
            PersonaPreset::Trader => (100_000_000, 1_000_000_000, 86_400),
            PersonaPreset::Degen => (1_000_000_000, 10_000_000_000, 604_800),
        };
        Self {
            schema_version: 1,
            preset,
            per_action_usd_micros,
            daily_usd_micros,
            session_duration_secs,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err("unsupported persona configuration version".into());
        }
        match self.preset {
            PersonaPreset::Custodian if self.per_action_usd_micros != 0 || self.daily_usd_micros != 0 || self.session_duration_secs != 0 =>
                Err("Custodian has no reusable session limits; choose Trader or Degen to propose a session".into()),
            PersonaPreset::Trader | PersonaPreset::Degen if self.per_action_usd_micros == 0 || self.daily_usd_micros == 0 || self.session_duration_secs == 0 =>
                Err("persona action/day caps and session duration must be positive".into()),
            _ if self.per_action_usd_micros > self.daily_usd_micros =>
                Err("persona per-action cap must not exceed its daily cap".into()),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_are_bounded_suggestions_and_custodian_is_default() {
        assert_eq!(PersonaConfig::default().preset, PersonaPreset::Custodian);
        for preset in [
            PersonaPreset::Custodian,
            PersonaPreset::Trader,
            PersonaPreset::Degen,
        ] {
            PersonaConfig::suggested(preset).validate().unwrap();
        }
        let mut invalid = PersonaConfig::suggested(PersonaPreset::Trader);
        invalid.daily_usd_micros = 1;
        assert!(invalid.validate().is_err());
    }
}
