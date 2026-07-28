package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// The jq programs shipped by io.5gpn.bilibili-cleaner. Two of them --
// clean-app-tab and clean-app-mine -- are upstream's own jq-path files inlined
// into the manifest; their cases assert only that they run, because their
// output is several kilobytes of replacement UI whose content is upstream's to
// define. The rest assert the transform.
//
// Copies of the shipped manifest, for the reason given in the zhihu file: gojq
// is the engine and Node has no jq.
var bilibiliJQCases = []struct {
	id      string
	program string
	input   string
	want    string
}{
	{
		id:      "clean-live-tracker-conf",
		program: `.data.domains=["wss://tracker.chat.bilibili.com"]`,
		input:   `{"data":{"domains":["wss://x"],"k":1}}`,
		want:    `{"data":{"domains":["wss://tracker.chat.bilibili.com"],"k":1}}`,
	},
	{
		id:      "clean-pd-proxy-tracker",
		program: `.data[][]?="stun.chat.bilibili.com:3478"`,
		input:   `{"data":[["a","b"]]}`,
		want:    `{"data":[["stun.chat.bilibili.com:3478","stun.chat.bilibili.com:3478"]]}`,
	},
	{
		id:      "clean-pgc-season",
		program: `del(.data.payment)`,
		input:   `{"data":{"payment":{"p":1},"t":"x"}}`,
		want:    `{"data":{"t":"x"}}`,
	},
	{
		id:      "clean-pgc-channel",
		program: `.data.modules |= map(select(.type != "TIP") | if .type == "BANNER" then .module_data.items |= map(select(.url | startswith("https://www.bilibili.com/blackboard/era/") | not)) else . end)`,
		input:   `{"data":{"modules":[{"type":"TIP"},{"type":"BANNER","module_data":{"items":[{"url":"https://www.bilibili.com/blackboard/era/a.html"},{"url":"https://ok"}]}}]}}`,
		want:    `{"data":{"modules":[{"type":"BANNER","module_data":{"items":[{"url":"https://ok"}]}}]}}`,
	},
	{
		id:      "clean-app-skin",
		program: `del(.data.common_equip)`,
		input:   `{"data":{"common_equip":1,"k":2}}`,
		want:    `{"data":{"k":2}}`,
	},
	{
		id: "clean-app-tab",
		program: `.data.tab = [
    {
        pos: 1,
        id: 731,
        name: "\u76F4\u64AD",
        tab_id: "\u76F4\u64ADtab",
        uri: "bilibili://live/home"
    },
    {
        pos: 2,
        id: 477,
        name: "\u63A8\u8350",
        tab_id: "\u63A8\u8350tab",
        uri: "bilibili://pegasus/promo",
        default_selected: 1
    },
    {
        pos: 3,
        id: 478,
        name: "\u70ED\u95E8",
        tab_id: "\u70ED\u95E8tab",
        uri: "bilibili://pegasus/hottopic"
    },
    {
        pos: 4,
        id: 3502,
        name: "\u52A8\u753B",
        tab_id: "bangumi",
        uri: "bilibili://pgc/bangumi_v2"
    },
    {
        pos: 5,
        id: 3503,
        name: "\u5F71\u89C6",
        tab_id: "film",
        uri: "bilibili://pgc/cinema_v2"
    }
] | 
.data.top = [
    {
        pos: 1,
        id: 176,
        name: "\u6D88\u606F",
        tab_id: "\u6D88\u606FTop",
        uri: "bilibili://link/im_home",
        icon: "http://i0.hdslb.com/bfs/archive/d43047538e72c9ed8fd8e4e34415fbe3a4f632cb.png"
    }
] | 
.data.bottom = [
    {
        pos: 1,
        id: 177,
        name: "\u9996\u9875",
        tab_id: "home",
        uri: "bilibili://main/home/",
        icon: "http://i0.hdslb.com/bfs/archive/63d7ee88d471786c1af45af86e8cb7f607edf91b.png",
        icon_selected: "http://i0.hdslb.com/bfs/archive/e5106aa688dc729e7f0eafcbb80317feb54a43bd.png"
    },
    {
        pos: 2,
        id: 179,
        name: "\u52A8\u6001",
        tab_id: "dynamic",
        uri: "bilibili://following/home/",
        icon: "http://i0.hdslb.com/bfs/archive/86dfbe5fa32f11a8588b9ae0fccb77d3c27cedf6.png",
        icon_selected: "http://i0.hdslb.com/bfs/archive/25b658e1f6b6da57eecba328556101dbdcb4b53f.png"
    },
    {
        pos: 5,
        id: 181,
        name: "\u6211\u7684",
        tab_id: "\u6211\u7684Bottom",
        uri: "bilibili://user_center/",
        icon: "http://i0.hdslb.com/bfs/archive/4b0b2c49ffeb4f0c2e6a4cceebeef0aab1c53fe1.png",
        icon_selected: "http://i0.hdslb.com/bfs/archive/a54a8009116cb896e64ef14dcf50e5cade401e00.png"
    }
]`,
		input: `{"data":{"tab":[{"old":1}]}}`,
		want:  ``,
	},
	{
		id:      "clean-app-splash",
		program: `.data |= with_entries(if .key | IN("show", "event_list") then .value = [] else . end)`,
		input:   `{"data":{"show":[1],"event_list":[2],"keep":3}}`,
		want:    `{"data":{"show":[],"event_list":[],"keep":3}}`,
	},
	{
		id:      "clean-app-feed",
		program: `if .data.items then .data.items |= map(select((.banner_item == null) and (.ad_info == null) and (.card_goto == "av") and (.card_type | IN("small_cover_v2", "large_cover_single_v9", "large_cover_v1")))) end`,
		input:   `{"data":{"items":[{"card_goto":"av","card_type":"small_cover_v2"},{"ad_info":{},"card_goto":"av","card_type":"small_cover_v2"},{"card_goto":"ad"}]}}`,
		want:    `{"data":{"items":[{"card_goto":"av","card_type":"small_cover_v2"}]}}`,
	},
	{
		id:      "clean-app-feed-story",
		program: `if .data.items then .data.items |= map(select((.ad_info == null) and (.card_goto | IN("vertical_ad_av", "vertical_ad_live", "vertical_ad_picture") | not)) | del(.story_cart_icon, .free_flow_toast, .image_infos, .course_info, .game_info)) end`,
		input:   `{"data":{"items":[{"card_goto":"story","game_info":{}},{"card_goto":"vertical_ad_av"},{"ad_info":{}}]}}`,
		want:    `{"data":{"items":[{"card_goto":"story"}]}}`,
	},
	{
		id: "clean-app-mine",
		program: `.data |= (
    del(.answer, .live_tip, .vip_section, .vip_section_v2, .modular_vip_section) | 
    .vip_type = 2 | 
    .vip |= if . != null and .status == 0 
        then . + { status: 1, type: 2, due_date: 9005270400000, role: 15 }
        else . 
    end | 
    if .sections_v2 then .sections_v2 = 
        [
            {
                "items": [
                    {
                        "id": 396,
                        "title": "离线缓存",
                        "uri": "bilibili://user_center/download",
                        "icon": "http://i0.hdslb.com/bfs/archive/5fc84565ab73e716d20cd2f65e0e1de9495d56f8.png",
                        "common_op_item": {}
                    },
                    {
                        "id": 397,
                        "title": "历史记录",
                        "uri": "bilibili://user_center/history",
                        "icon": "http://i0.hdslb.com/bfs/archive/8385323c6acde52e9cd52514ae13c8b9481c1a16.png",
                        "common_op_item": {}
                    },
                    {
                        "id": 3072,
                        "title": "我的收藏",
                        "uri": "bilibili://user_center/favourite?version=2",
                        "icon": "http://i0.hdslb.com/bfs/archive/d79b19d983067a1b91614e830a7100c05204a821.png",
                        "common_op_item": {}
                    },
                    {
                        "id": 2830,
                        "title": "稍后再看",
                        "uri": "bilibili://user_center/watch_later_v2",
                        "icon": "http://i0.hdslb.com/bfs/archive/63bb768caa02a68cb566a838f6f2415f0d1d02d6.png",
                        "need_login": 1,
                        "common_op_item": {}
                    }
                ],
                "style": 1,
                "button": {}
            },
            {
                "title": "推荐服务",
                "items": [
                    {
                        "id": 402,
                        "title": "个性装扮",
                        "uri": "https://www.bilibili.com/h5/mall/home?navhide=1&f_source=shop&from=myservice",
                        "icon": "http://i0.hdslb.com/bfs/archive/0bcad10661b50f583969b5a188c12e5f0731628c.png",
                        "common_op_item": {}
                    },
                    {
                        "id": 622,
                        "title": "会员购",
                        "uri": "bilibili://mall/home",
                        "icon": "http://i0.hdslb.com/bfs/archive/19c794f01def1a267b894be84427d6a8f67081a9.png",
                        "common_op_item": {}
                    },
                    {
                        "id": 404,
                        "title": "我的钱包",
                        "uri": "bilibili://bilipay/mine_wallet",
                        "icon": "http://i0.hdslb.com/bfs/archive/f416634e361824e74a855332b6ff14e2e7c2e082.png",
                        "common_op_item": {}
                    },
                    {
                        "id": 406,
                        "title": "我的直播",
                        "uri": "bilibili://user_center/live_center",
                        "icon": "http://i0.hdslb.com/bfs/archive/1db5791746a0112890b77a0236baf263d71ecb27.png",
                        "common_op_item": {},
                    }
                ],
                "style": 1,
                "button": {}
            },
            {
                "title": "更多服务",
                "items": [
                    {
                        "id": 407,
                        "title": "联系客服",
                        "uri": "bilibili://user_center/feedback",
                        "icon": "http://i0.hdslb.com/bfs/archive/7ca840cf1d887a45ee1ef441ab57845bf26ef5fa.png",
                        "common_op_item": {}
                    },
                    {
                        "id": 410,
                        "title": "设置",
                        "uri": "bilibili://user_center/setting",
                        "icon": "http://i0.hdslb.com/bfs/archive/e932404f2ee62e075a772920019e9fbdb4b5656a.png",
                        "common_op_item": {}
                    }
                ],
                "style": 2,
                "button": {}
            }
        ]
    end | 
    if .ipad_sections then .ipad_sections = 
        [
            {
                "id": 747,
                "title": "离线缓存",
                "uri": "bilibili://user_center/download",
                "icon": "http://i0.hdslb.com/bfs/feed-admin/9bd72251f7366c491cfe78818d453455473a9678.png",
                "mng_resource": { "icon_id": 0, "icon": "" }
            },
            {
                "id": 748,
                "title": "历史记录",
                "uri": "bilibili://user_center/history",
                "icon": "http://i0.hdslb.com/bfs/feed-admin/83862e10685f34e16a10cfe1f89dbd7b2884d272.png",
                "mng_resource": { "icon_id": 0, "icon": "" }
            },
            {
                "id": 749,
                "title": "我的收藏",
                "uri": "bilibili://user_center/favourite",
                "icon": "http://i0.hdslb.com/bfs/feed-admin/6ae7eff6af627590fc4ed80c905e9e0a6f0e8188.png",
                "mng_resource": { "icon_id": 0, "icon": "" }
            },
            {
                "id": 750,
                "title": "稍后再看",
                "uri": "bilibili://user_center/watch_later",
                "icon": "http://i0.hdslb.com/bfs/feed-admin/928ba9f559b02129e51993efc8afe95014edec94.png",
                "mng_resource": { "icon_id": 0, "icon": "" }
            }
        ] 
    end | 
    if .ipad_upper_sections then .ipad_upper_sections = 
        [
            {
                "id": 752,
                "title": "创作首页",
                "uri": "/uper/homevc",
                "icon": "http://i0.hdslb.com/bfs/feed-admin/d20dfed3b403c895506b1c92ecd5874abb700c01.png",
                "mng_resource": { "icon_id": 0, "icon": "" }
            }
        ] 
    end | 
    if .ipad_recommend_sections then .ipad_recommend_sections = 
        [
            {
                "id": 755,
                "title": "我的关注",
                "uri": "bilibili://user_center/myfollows",
                "icon": "http://i0.hdslb.com/bfs/feed-admin/fdd7f676030c6996d36763a078442a210fc5a8c0.png",
                "mng_resource": { "icon_id": 0, "icon": "" }
            },
            {
                "id": 756,
                "title": "我的消息",
                "uri": "bilibili://link/im_home",
                "icon": "http://i0.hdslb.com/bfs/feed-admin/e1471740130a08a48b02a4ab29ed9d5f2281e3bf.png",
                "mng_resource": { "icon_id": 0, "icon": "" }
            }
        ] 
    end | 
    if .ipad_more_sections then .ipad_more_sections = 
        [
            {
                "id": 763,
                "title": "我的客服",
                "uri": "bilibili://user_center/feedback",
                "icon": "http://i0.hdslb.com/bfs/feed-admin/7801a6180fb67cf5f8ee05a66a4668e49fb38788.png",
                "mng_resource": { "icon_id": 0, "icon": "" }
            },
            {
                "id": 764,
                "title": "设置",
                "uri": "bilibili://user_center/setting",
                "icon": "http://i0.hdslb.com/bfs/feed-admin/34e8faea00b3dd78977266b58d77398b0ac9410b.png",
                "mng_resource": { "icon_id": 0, "icon": "" }
            }
        ] 
    end 
)`,
		input: `{"data":{"answer":1,"vip":{"status":0},"keep":2}}`,
		want:  ``,
	},
	{
		id:      "clean-app-myinfo",
		program: `.data.vip |= if . != null and .status == 0 then . + { status: 1, type: 2, due_date: 9005270400000, role: 15 } else . end`,
		input:   `{"data":{"vip":{"status":0}}}`,
		want:    `{"data":{"vip":{"status":1,"type":2,"due_date":9005270400000,"role":15}}}`,
	},
}

func TestBilibiliShippedJQPrograms(t *testing.T) {
	t.Parallel()
	for _, testCase := range bilibiliJQCases {
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
			if testCase.want == "" {
				if len(got) == 0 {
					t.Fatal("program produced no output")
				}
				return
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
