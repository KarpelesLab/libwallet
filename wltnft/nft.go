package wltnft

import (
	"time"

	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
)

type NftAttribute struct {
	TraitType   string `json:"trait_type,omitempty"`
	DisplayType string `json:"display_type,omitempty"`
	Value       any    `json:"value"`
}

type Nft struct {
	TableName       psql.Name       `sql:"Nft"`
	Id              *xuid.XUID      `json:"id,omitempty" sql:",key=PRIMARY"`
	Key             string          `json:"key" sql:",type=VARCHAR,size=255,key=UNIQUE:Key"`
	ContractAddress string          `json:"contract_address" sql:",type=VARCHAR,size=255"`
	ContractName    string          `json:"contract_name" sql:",type=VARCHAR,size=255"`
	TokenId         string          `json:"token_id" sql:",type=VARCHAR,size=255"`
	Name            string          `json:"name" sql:",type=VARCHAR,size=255"`
	Description     string          `json:"description,omitempty" sql:",type=TEXT"`
	Image           string          `json:"image,omitempty" sql:",type=TEXT"`
	ImageUrl        string          `json:"image_url,omitempty" sql:",type=TEXT"`
	AnimationUrl    string          `json:"animation_url,omitempty" sql:",type=TEXT"`
	BackgroundColor string          `json:"background_color,omitempty" sql:",type=VARCHAR,size=255"`
	YoutubeUrl      string          `json:"youtube_url,omitempty" sql:",type=TEXT"`
	ExternalUrl     string          `json:"external_url,omitempty" sql:",type=TEXT"`
	Decimals        string          `json:"decimals,omitempty" sql:",type=VARCHAR,size=255"`
	Attributes      []*NftAttribute `json:"attributes" sql:",type=JSON,format=json"`
	Network         *xuid.XUID      `json:"network,omitempty" sql:",type=VARCHAR,size=255"`
	Created         time.Time       `sql:",type=DATETIME"`
	Updated         time.Time       `sql:",type=DATETIME"`
}
