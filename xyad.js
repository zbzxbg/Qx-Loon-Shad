const url = $request.url;
let body = $response.body;

try {
    let obj = JSON.parse(body);

    if (url.indexOf("/ad/get_ad_data") !== -1) {
        obj.ad_data = null;
        obj.expire_ts = 0;
        obj.trace_info_str = "";
    }
    else if (url.indexOf("/ad/get_app_splash") !== -1) {
        obj.app_open_splash_data_list = [];
        if (obj.app_open_splash_detail) {
            obj.app_open_splash_detail.limit_per_day = 0;
            obj.app_open_splash_detail.min_interval = 0;
            obj.app_open_splash_detail.skip_time = 0;
        }
    }
    else if (url.indexOf("/ad/get_draw_gem_progress") !== -1) {
        obj.is_show = false;
        obj.draw_count = 0;
        obj.draw_limit = 0;
        obj.cooldown_seconds = 0;
    }
    else if (url.indexOf("/payment/get_pop_info") !== -1) {
        obj.banner_item = null;
        if (obj.banner_list) obj.banner_list = [];
        if (obj.ad_banner_item) obj.ad_banner_item = null;
        if (obj.pop_banner) obj.pop_banner = null;
    }

    body = JSON.stringify(obj);
} catch (e) {
    console.log("xingyeAdBlock parse error: " + e.message);
}

$done({ body });
