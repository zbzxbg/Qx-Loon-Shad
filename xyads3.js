const url = $request.url;
let body = $response.body;

if (body) {
    try {
        let obj = JSON.parse(body);

        // 1. 隐藏 Tab 栏中的特定分类（如：星工坊、挑战）
        if (url.includes("/feed/get_feed_tab")) {
            if (obj.tab_list && obj.tab_list[0] && obj.tab_list[0].sub_tab_list) {
                obj.tab_list[0].sub_tab_list = obj.tab_list[0].sub_tab_list.filter(item => {
                    return item.name !== "星工坊" && item.name !== "挑战";
                });
            }
        }

        // 2. 隐藏抽奖/活动入口
        else if (url.includes("/ad/get_draw_gem_progress")) {
            if (obj.hasOwnProperty("is_show")) {
                obj.is_show = false;
            }
        }

        // 3. 修改用户设置（隐藏动态入口）
        else if (obj.user_settings) {
            obj.user_settings.enable_moment = false;
            obj.user_settings.enable_moment_scene_repeat_show = false;
        }

        $done({ body: JSON.stringify(obj) });
    } catch (e) {
        console.log("合一脚本运行异常: " + e);
        $done({});
    }
} else {
    $done({});
}
