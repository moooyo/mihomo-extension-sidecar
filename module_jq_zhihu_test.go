package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// The jq programs shipped by io.5gpn.zhihu-cleaner, with a case each.
//
// They live here rather than in the extensions repository because gojq is the
// engine that runs them and Node has no jq, so that repository can check their
// structure and path patterns but cannot execute them. These are copies of the
// shipped manifest: changing an expression there means changing it here, and
// the extension's README records the pairing.
var zhihuJQCases = []struct {
	id      string
	program string
	input   string
	want    string
}{
	{
		id:      "clean-transport-config",
		program: `def drop_keys: {"km_httpdns_new_config_tars":true,"preFetchHttpDns":true,"httpdns_detector_use_concurrent":true,"httpdns_use_memory_cache":true,"httpdns_new_config_tars":true,"coreNetworkConf_useTars":true,"km_coreNetworkConf_useTars":true,"sugarQuicConfig":true,"quic_dns_detect_enable":true,"quicMixAB":true,"quic_downgrade_enable":true,"quic_priority_strategy":true,"quic_check_health_enable":true,"tquic_configuration":true,"networkExprimentList":true,"tars_ab_list":true,"zaSetExtraRequestHeader":true}; .data.configs |= map(select((drop_keys[.configKey] // false) | not) | if (.configValue | type) == "object" then del(.configValue.delayHttpdns, .configValue.dnsParser, .configValue.HTTPDNS) else . end)`,
		input:   `{"data":{"configs":[{"configKey":"quicMixAB"},{"configKey":"ok","configValue":{"HTTPDNS":1,"keep":2}}]}}`,
		want:    `{"data":{"configs":[{"configKey":"ok","configValue":{"keep":2}}]}}`,
	},
	{
		id:      "clean-answer-responses",
		program: `del(.third_business, .float_search_word, .ring_info, .interaction_bar_plugins) | if (.structured_content | type) == "object" then .structured_content.segments |= (if type == "array" then map(select(.type != "card")) else . end) else . end`,
		input:   `{"third_business":1,"float_search_word":2,"ring_info":3,"interaction_bar_plugins":4,"keep":5,"structured_content":{"segments":[{"type":"card"},{"type":"text"}]}}`,
		want:    `{"keep":5,"structured_content":{"segments":[{"type":"text"}]}}`,
	},
	{
		id:      "clean-root-tab",
		program: `.tab_list |= (if type == "array" then map(select(.tab_type == "follow" or .tab_type == "hot" or .tab_type == "recommend")) else . end) | if (.ring_list | type) == "array" then .ring_list = [] else . end | if (.tab_ext | type) == "object" and (.tab_ext | has("is_show_ring")) then .tab_ext.is_show_ring = false else . end`,
		input:   `{"tab_list":[{"tab_type":"follow"},{"tab_type":"ring_tab"},{"tab_type":"hot"}],"ring_list":[1,2],"tab_ext":{"is_show_ring":true}}`,
		want:    `{"tab_list":[{"tab_type":"follow"},{"tab_type":"hot"}],"ring_list":[],"tab_ext":{"is_show_ring":false}}`,
	},
	{
		id:      "clean-topstory-recommend",
		program: `def marker($v): ($v | type) as $t | if $t == "boolean" then $v elif $t == "string" then $v != "" elif $t == "number" then $v != 0 elif $t == "array" then ($v | length) > 0 elif $t == "object" then ($v | length) > 0 else false end; def lower($v): if ($v | type) == "string" then ($v | ascii_downcase) else "" end; def blocked: ["ad","adcard","advertisement","commercial","commercialcard","market_card","marketcard","promotion","promotioncard"]; .data |= (if type == "array" then map(select((type != "object") or ((marker(.ad_info) | not) and (marker(.commercial_info) | not) and (marker(.promotion_info) | not) and (.is_ad != true) and (.is_commercial != true) and (lower(.type) as $t | lower(.card_type) as $c | lower(.target.type) as $g | ((blocked | index($t)) | not) and ((blocked | index($c)) | not) and ((blocked | index($g)) | not))))) else . end) | .data |= (if type == "array" then map(if (type == "object") and ((.children | type) == "array") then .children |= map(select((type != "object") or (.id != "ring"))) else . end) else . end)`,
		input:   `{"data":[{"id":"keep","children":[{"id":"ring"},{"id":"x"}]},{"ad_info":{"a":1}},{"is_ad":true},{"type":"AdCard"},{"card_type":"promotion"},{"target":{"type":"COMMERCIAL"}},{"commercial_info":""}]}`,
		want:    `{"data":[{"id":"keep","children":[{"id":"x"}]},{"commercial_info":""}]}`,
	},
	{
		id:      "clean-question-feeds",
		program: `del(.ad_info)`,
		input:   `{"ad_info":{},"keep":1}`,
		want:    `{"keep":1}`,
	},
	{
		id:      "clean-root-comment",
		program: `del(.atmosphere_voting_config)`,
		input:   `{"atmosphere_voting_config":1,"keep":2}`,
		want:    `{"keep":2}`,
	},
	{
		id:      "clean-article-pin",
		program: `del(.third_business, .ring_info, .interaction_bar_plugins)`,
		input:   `{"third_business":1,"ring_info":2,"interaction_bar_plugins":3,"keep":4}`,
		want:    `{"keep":4}`,
	},
	{
		id:      "clean-comment-list-headers",
		program: `del(.continuous_consumption_module)`,
		input:   `{"continuous_consumption_module":1,"keep":2}`,
		want:    `{"keep":2}`,
	},
	{
		id:      "clean-podcast-hub",
		program: `del(.banners)`,
		input:   `{"banners":[1],"keep":2}`,
		want:    `{"keep":2}`,
	},
	{
		id:      "clean-search-recommend-query",
		program: `if (.recommend_queries | type) == "object" then .recommend_queries.queries |= (if type == "array" then map(select(.type == "normal")) else . end) else . end`,
		input:   `{"recommend_queries":{"queries":[{"type":"normal"},{"type":"ad"}]}}`,
		want:    `{"recommend_queries":{"queries":[{"type":"normal"}]}}`,
	},
	{
		id:      "clean-search-result",
		program: `del(.pendant)`,
		input:   `{"pendant":1,"keep":2}`,
		want:    `{"keep":2}`,
	},
	{
		id:      "clean-search-tabs",
		program: `.data |= (if type == "array" then map(select(.t as $t | ["ai_zhida","column","favlist","general","km_general","people","pin","podcast","publication","recent","ring","scholar","topic","zvideo"] | index($t))) else . end)`,
		input:   `{"data":[{"t":"general"},{"t":"ad"},{"t":"people"}]}`,
		want:    `{"data":[{"t":"general"},{"t":"people"}]}`,
	},
	{
		id:      "clean-people-self",
		program: `if (.vip_info | type) == "object" then del(.vip_info.entrance_v2) | (if (.vip_info.entrance_new | type) == "object" then del(.vip_info.entrance_new.right_button) else . end) else . end`,
		input:   `{"vip_info":{"entrance_v2":1,"entrance_new":{"right_button":2,"keep":3},"keep":4}}`,
		want:    `{"vip_info":{"entrance_new":{"keep":3},"keep":4}}`,
	},
}

func TestZhihuShippedJQPrograms(t *testing.T) {
	t.Parallel()
	for _, testCase := range zhihuJQCases {
		t.Run(testCase.id, func(t *testing.T) {
			code, err := compileJQProgram(testCase.program)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			got, err := runJQ(ctx, code, []byte(testCase.input), nil)
			if err != nil {
				t.Fatal(err)
			}
			var gotValue, wantValue any
			if err := json.Unmarshal(got, &gotValue); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(testCase.want), &wantValue); err != nil {
				t.Fatal(err)
			}
			gotText, _ := json.Marshal(gotValue)
			wantText, _ := json.Marshal(wantValue)
			if string(gotText) != string(wantText) {
				t.Fatalf("\n got %s\nwant %s", gotText, wantText)
			}
		})
	}
}
