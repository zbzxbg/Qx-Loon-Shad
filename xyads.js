// 获取服务器返回的原始数据
let body = $response.body;

if (body) {
    try {
        // 1. 将字符串格式的数据转换为 JSON 对象
        let obj = JSON.parse(body);
        
        // 2. 找到 is_show 字段，并将其修改为 false
        if (obj.hasOwnProperty('is_show')) {
            obj.is_show = false;
        }
        
        // 也可以顺便把抽奖次数限制改大（前端自慰，纯视觉效果）
        // if (obj.draw_limit) obj.draw_limit = 999;
        
        // 3. 将修改后的 JSON 对象重新转换回字符串，并返回给 APP
        $done({ body: JSON.stringify(obj) });
        
    } catch (e) {
        // 如果解析报错，原样返回，防止 APP 崩溃
        console.log("脚本解析修改失败: " + e);
        $done({});
    }
} else {
    // 如果没有获取到数据，直接返回
    $done({});
}
