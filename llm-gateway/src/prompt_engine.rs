use crate::{
    config::{GatewayConfig, SkillLevel},
    error::{GatewayError, GatewayResult},
    models::Message,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};
use tera::{Tera, Context};

pub struct PromptEngine {
    config: Arc<GatewayConfig>,
    tera: Arc<Tera>,
    templates: Arc<HashMap<String, PromptTemplate>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptTemplate {
    pub name: String,
    pub description: String,
    pub skill_level: SkillLevel,
    pub system_prompt: String,
    pub user_template: String,
    pub variables: Vec<TemplateVariable>,
    pub metadata: TemplateMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVariable {
    pub name: String,
    pub description: String,
    pub required: bool,
    pub default: Option<String>,
    pub variable_type: VariableType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VariableType {
    String,
    Integer,
    Float,
    Boolean,
    Array,
    Object,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TemplateMetadata {
    pub version: String,
    pub author: String,
    pub tags: Vec<String>,
    pub estimated_tokens: usize,
    pub max_tokens: usize,
    pub temperature: Option<f32>,
}

impl PromptEngine {
    pub fn new(config: Arc<GatewayConfig>) -> GatewayResult<Self> {
        let templates_dir = &config.prompt_engine.templates_dir;
        let tera = Tera::new(&format!("{}/**/*", templates_dir))
            .map_err(|e| GatewayError::Config(format!("Failed to initialize template engine: {}", e)))?;

        let templates = Self::load_templates(templates_dir)?;

        Ok(Self {
            config,
            tera: Arc::new(tera),
            templates: Arc::new(templates),
        })
    }

    fn load_templates(dir: &str) -> GatewayResult<HashMap<String, PromptTemplate>> {
        let mut templates = HashMap::new();
        let path = Path::new(dir);

        if !path.exists() {
            warn!("Templates directory does not exist: {}", dir);
            return Ok(templates);
        }

        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                let content = fs::read_to_string(&path)?;
                let template: PromptTemplate = toml::from_str(&content)
                    .map_err(|e| GatewayError::Config(format!("Failed to parse template {}: {}", path.display(), e)))?;
                templates.insert(template.name.clone(), template);
            }
        }

        info!("Loaded {} prompt templates", templates.len());
        Ok(templates)
    }

    pub fn render(&self, template_name: &str, variables: HashMap<String, serde_json::Value>) -> GatewayResult<String> {
        let template = self.templates.get(template_name)
            .ok_or_else(|| GatewayError::TemplateNotFound(template_name.to_string()))?;

        let mut context = Context::new();
        for (key, value) in variables {
            context.insert(key, &value);
        }

        for var in &template.variables {
            if var.required && !context.contains_key(&var.name) {
                if let Some(default) = &var.default {
                    context.insert(&var.name, default);
                } else {
                    return Err(GatewayError::Config(format!("Required variable '{}' not provided for template '{}'", var.name, template_name)));
                }
            }
        }

        self.tera.render(&format!("{}.tera", template_name), &context)
            .map_err(|e| GatewayError::Config(format!("Template render error: {}", e)))
    }

    pub fn render_system(&self, template_name: &str, variables: HashMap<String, serde_json::Value>) -> GatewayResult<String> {
        let template = self.templates.get(template_name)
            .ok_or_else(|| GatewayError::TemplateNotFound(template_name.to_string()))?;

        let mut context = Context::new();
        for (key, value) in variables {
            context.insert(key, &value);
        }

        let system_template = format!("{}_system", template_name);
        self.tera.render(&format!("{}.tera", system_template), &context)
            .map_err(|e| GatewayError::Config(format!("System template render error: {}", e)))
            .or_else(|_| Ok(template.system_prompt.clone()))
    }

    pub fn get_template(&self, name: &str) -> Option<&PromptTemplate> {
        self.templates.get(name)
    }

    pub fn list_templates(&self) -> Vec<&PromptTemplate> {
        self.templates.values().collect()
    }

    pub fn list_templates_by_skill(&self, skill: SkillLevel) -> Vec<&PromptTemplate> {
        self.templates.values().filter(|t| t.skill_level == skill).collect()
    }

    pub fn detect_skill_level(&self, messages: &[Message]) -> SkillLevel {
        if !self.config.prompt_engine.auto_detect_skill {
            return self.config.prompt_engine.default_skill_level;
        }

        for msg in messages {
            if msg.role == crate::models::Role::System {
                if let Some(text) = msg.content.as_text() {
                    let text_lower = text.to_lowercase();
                    if text_lower.contains("apt") || text_lower.contains("advanced persistent") {
                        return SkillLevel::Apt;
                    }
                    if text_lower.contains("expert") || text_lower.contains("senior") {
                        return SkillLevel::Expert;
                    }
                    if text_lower.contains("intermediate") || text_lower.contains("mid") {
                        return SkillLevel::Intermediate;
                    }
                    if text_lower.contains("novice") || text_lower.contains("beginner") || text_lower.contains("junior") {
                        return SkillLevel::Novice;
                    }
                }
            }
        }
        self.config.prompt_engine.default_skill_level
    }

    pub fn build_messages(&self, template_name: &str, variables: HashMap<String, serde_json::Value>, user_input: &str) -> GatewayResult<Vec<Message>> {
        let _template = self.templates.get(template_name)
            .ok_or_else(|| GatewayError::TemplateNotFound(template_name.to_string()))?;

        let mut vars = variables;
        vars.insert("user_input".to_string(), serde_json::Value::String(user_input.to_string()));

        let system_prompt = self.render_system(template_name, vars.clone())?;
        let user_prompt = self.render(template_name, vars)?;

        Ok(vec![
            Message::system(system_prompt),
            Message::user(user_prompt),
        ])
    }
}

impl Default for PromptTemplate {
    fn default() -> Self {
        Self {
            name: "default".into(),
            description: "Default template".into(),
            skill_level: SkillLevel::Intermediate,
            system_prompt: "You are a helpful assistant.".into(),
            user_template: "{{user_input}}".into(),
            variables: vec![],
            metadata: TemplateMetadata::default(),
        }
    }
}