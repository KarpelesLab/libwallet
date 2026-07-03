//! wltnft (Nft model) — port of the Go `wltnft` package.
//!
//! Read surface: fetch/list. Lowercase JSON keys (Go json tags) with Created/
//! Updated PascalCase; DB columns are the PascalCase field names. Attributes
//! are stored as JSON. NFTs are populated by discovery (RPC) — no create.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::{Env, Result, SqlValue};

const TABLE_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "Nft" ("Id" text, "Key" text, "ContractAddress" text, "ContractName" text, "TokenId" text, "Name" text, "Description" text, "Image" text, "ImageUrl" text, "AnimationUrl" text, "BackgroundColor" text, "YoutubeUrl" text, "ExternalUrl" text, "Decimals" text, "Attributes" text, "Network" text, "Created" text, "Updated" text, PRIMARY KEY ("Id"));
CREATE UNIQUE INDEX IF NOT EXISTS "Nft_Key" ON "Nft" ("Key");"#;
const COLS: &str = r#""Id", "Key", "ContractAddress", "ContractName", "TokenId", "Name", "Description", "Image", "ImageUrl", "AnimationUrl", "BackgroundColor", "YoutubeUrl", "ExternalUrl", "Decimals", "Attributes", "Network", "Created", "Updated""#;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct NftAttribute {
    #[serde(rename = "trait_type", default, skip_serializing_if = "String::is_empty")]
    pub trait_type: String,
    #[serde(rename = "display_type", default, skip_serializing_if = "String::is_empty")]
    pub display_type: String,
    #[serde(rename = "value", default)]
    pub value: Value,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Nft {
    #[serde(rename = "id", default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(rename = "key", default)]
    pub key: String,
    #[serde(rename = "contract_address", default)]
    pub contract_address: String,
    #[serde(rename = "contract_name", default)]
    pub contract_name: String,
    #[serde(rename = "token_id", default)]
    pub token_id: String,
    #[serde(rename = "name", default)]
    pub name: String,
    #[serde(rename = "description", default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(rename = "image", default, skip_serializing_if = "String::is_empty")]
    pub image: String,
    #[serde(rename = "image_url", default, skip_serializing_if = "String::is_empty")]
    pub image_url: String,
    #[serde(rename = "animation_url", default, skip_serializing_if = "String::is_empty")]
    pub animation_url: String,
    #[serde(rename = "background_color", default, skip_serializing_if = "String::is_empty")]
    pub background_color: String,
    #[serde(rename = "youtube_url", default, skip_serializing_if = "String::is_empty")]
    pub youtube_url: String,
    #[serde(rename = "external_url", default, skip_serializing_if = "String::is_empty")]
    pub external_url: String,
    #[serde(rename = "decimals", default, skip_serializing_if = "String::is_empty")]
    pub decimals: String,
    #[serde(rename = "attributes", default)]
    pub attributes: Vec<NftAttribute>,
    #[serde(rename = "network", default, skip_serializing_if = "String::is_empty")]
    pub network: String,
    #[serde(rename = "Created", default)]
    pub created: String,
    #[serde(rename = "Updated", default)]
    pub updated: String,
}

pub fn init(env: &Env) -> Result<()> {
    env.ensure_table(TABLE_DDL)
}

pub fn fetch(env: &Env, id: &str) -> Result<Option<Nft>> {
    let sql = format!(r#"SELECT {COLS} FROM "Nft" WHERE "Id" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(id.to_owned())])?;
    Ok(rows.first().map(|r| row_to_nft(r)))
}

pub fn list(env: &Env) -> Result<Vec<Nft>> {
    let sql = format!(r#"SELECT {COLS} FROM "Nft" ORDER BY "Key" ASC"#);
    let rows = env.query(&sql, Vec::new())?;
    Ok(rows.iter().map(|r| row_to_nft(r)).collect())
}

fn row_to_nft(row: &[SqlValue]) -> Nft {
    let text = |i: usize| row.get(i).and_then(|v| v.as_text()).unwrap_or("").to_owned();
    let attributes = row
        .get(14)
        .and_then(|v| v.as_text())
        .and_then(|s| serde_json::from_str::<Vec<NftAttribute>>(s).ok())
        .unwrap_or_default();
    Nft {
        id: text(0),
        key: text(1),
        contract_address: text(2),
        contract_name: text(3),
        token_id: text(4),
        name: text(5),
        description: text(6),
        image: text(7),
        image_url: text(8),
        animation_url: text(9),
        background_color: text(10),
        youtube_url: text(11),
        external_url: text(12),
        decimals: text(13),
        attributes,
        network: text(15),
        created: text(16),
        updated: text(17),
    }
}
