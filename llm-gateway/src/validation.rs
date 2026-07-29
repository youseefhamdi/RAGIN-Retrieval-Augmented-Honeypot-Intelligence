use crate::{
    config::{FilterAction, GatewayConfig},
    error::{GatewayError, GatewayResult},
    models::ChatResponse,
};
use regex::Regex;
use tracing::{debug, warn};

pub struct ResponseValidator {
    config: Arc<GatewayConfig>,
    filters: Vec<CompiledFilter>,
}

struct CompiledFilter {
    name: String,
    regex: Regex,
    action: FilterAction,
}

use std::sync::Arc;

impl ResponseValidator {
    pub fn new(config: Arc<GatewayConfig>) -> GatewayResult<Self> {
        let mut filters = Vec::new();
        for filter in &config.validation.content_filters {
            let regex = Regex::new(&filter.pattern)
                .map_err(|e| GatewayError::Config(format!("Invalid regex in filter {}: {}", filter.name, e)))?;
            filters.push(CompiledFilter {
                name: filter.name.clone(),
                regex,
                action: filter.action.clone(),
            });
        }
        Ok(Self { config, filters })
    }

    pub fn validate(&self, response: &ChatResponse) -> GatewayResult<ValidationResult> {
        if !self.config.validation.enabled {
            return Ok(ValidationResult::valid());
        }

        let mut result = ValidationResult::valid();

        for choice in &response.choices {
            if let Some(content) = choice.message.content.as_text() {
                for filter in &self.filters {
                    if filter.regex.is_match(content) {
                        match filter.action {
                            FilterAction::Block => {
                                result.add_violation(format!("Content blocked by filter: {}", filter.name));
                                return Err(GatewayError::ContentFiltered(filter.name.clone()));
                            }
                            FilterAction::Warn => {
                                result.add_warning(format!("Content flagged by filter: {}", filter.name));
                                warn!("Content filter '{}' matched response", filter.name);
                            }
                            FilterAction::Redact => {
                                result.add_info(format!("Content redacted by filter: {}", filter.name));
                                debug!("Content filter '{}' would redact content", filter.name);
                            }
                        }
                    }
                }
            }

            if let Some(reason) = &choice.finish_reason {
                if !self.config.validation.allowed_finish_reasons.contains(reason) {
                    result.add_violation(format!("Invalid finish reason: {}", reason));
                }
            }

            if let Some(usage) = Some(&response.usage) {
                if usage.completion_tokens > self.config.validation.max_tokens_per_response {
                    result.add_violation(format!("Response exceeds max tokens: {} > {}", usage.completion_tokens, self.config.validation.max_tokens_per_response));
                }
            }
        }

        if self.config.validation.strict_mode && !result.is_valid() {
            return Err(GatewayError::Validation(result.violations.join(", ")));
        }

        Ok(result)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    pub valid: bool,
    pub violations: Vec<String>,
    pub warnings: Vec<String>,
    pub info: Vec<String>,
}

impl ValidationResult {
    pub fn valid() -> Self {
        Self { valid: true, violations: vec![], warnings: vec![], info: vec![] }
    }

    pub fn add_violation(&mut self, msg: String) {
        self.valid = false;
        self.violations.push(msg);
    }

    pub fn add_warning(&mut self, msg: String) {
        self.warnings.push(msg);
    }

    pub fn add_info(&mut self, msg: String) {
        self.info.push(msg);
    }

    pub fn is_valid(&self) -> bool {
        self.valid && self.violations.is_empty()
    }

    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }
}