# -*- coding: utf-8 -*-
"""
部署到 Render 后，运行此脚本更新 Gitee 配置中的 wan_url。
用法: python update_gitee_wan_url.py https://your-app.onrender.com
"""
import sys, json, requests, os

GITEE_USER = "morning-morning-morning-flight"
GITEE_REPO = "en-config"
GITEE_BRANCH = "master"
GITEE_TOKEN = os.environ.get("GITEE_TOKEN", "")
CONFIG_PATH = "server_config.json"

def get_gitee_token():
    """从环境变量或 token.txt 读取 Gitee token"""
    if GITEE_TOKEN:
        return GITEE_TOKEN
    token_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gitee_token.txt")
    if os.path.exists(token_file):
        with open(token_file, "r") as f:
            return f.read().strip()
    print("[ERROR] 请设置 GITEE_TOKEN 环境变量，或在当前目录创建 gitee_token.txt 文件写入 token")
    sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print("用法: python update_gitee_wan_url.py https://your-app.onrender.com")
        sys.exit(1)

    new_url = sys.argv[1].rstrip("/")
    token = get_gitee_token()

    print(f"[1] 读取当前 Gitee 配置...")
    api = f"https://gitee.com/api/v5/repos/{GITEE_USER}/{GITEE_REPO}/contents/{CONFIG_PATH}?ref={GITEE_BRANCH}&access_token={token}"
    r = requests.get(api, timeout=15)
    if r.status_code != 200:
        print(f"[ERROR] 读取失败: {r.status_code} {r.text[:200]}")
        sys.exit(1)

    import base64
    data = r.json()
    sha = data.get("sha", "")
    old_content = base64.b64decode(data["content"]).decode("utf-8")
    config = json.loads(old_content)
    old_url = config.get("wan_url", "(无)")
    print(f"    当前 wan_url: {old_url}")
    print(f"    新 wan_url:   {new_url}")

    # 更新配置
    config["wan_url"] = new_url
    config["local_url"] = new_url
    config["localhost_url"] = new_url
    config["updated_at"] = int(__import__("time").time())
    config["provider"] = "render"
    config["tunnel_name"] = "render-cloud"

    new_content = json.dumps(config, indent=2, ensure_ascii=False)

    print(f"\n[2] 更新 Gitee 配置...")
    put_api = f"https://gitee.com/api/v5/repos/{GITEE_USER}/{GITEE_REPO}/contents/{CONFIG_PATH}"
    body = {
        "access_token": token,
        "content": base64.b64encode(new_content.encode("utf-8")).decode("utf-8"),
        "sha": sha,
        "message": f"update wan_url -> {new_url}",
        "branch": GITEE_BRANCH,
    }
    r2 = requests.put(put_api, json=body, timeout=15)
    if r2.status_code in (200, 201):
        print(f"    [OK] Gitee 配置更新成功!")
    else:
        print(f"    [ERROR] 更新失败: {r2.status_code} {r2.text[:200]}")
        sys.exit(1)

    # 同时更新 GitHub Gist（如果有 token）
    gh_token = os.environ.get("GH_TOKEN", os.environ.get("GITHUB_TOKEN", ""))
    if gh_token:
        print(f"\n[3] 更新 GitHub Gist...")
        # 读取现有 gist
        gist_id_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gist_id.txt")
        if os.path.exists(gist_id_file):
            gist_id = open(gist_id_file).read().strip()
            gist_api = f"https://api.github.com/gists/{gist_id}"
            headers = {"Authorization": f"token {gh_token}", "Accept": "application/vnd.github.v3+json"}
            body3 = {
                "description": "EN server config",
                "files": {
                    "server_config.json": {
                        "content": new_content
                    }
                }
            }
            r3 = requests.patch(gist_api, headers=headers, json=body3, timeout=15)
            if r3.status_code == 200:
                print(f"    [OK] Gist 更新成功!")
            else:
                print(f"    [SKIP] Gist 更新失败: {r3.status_code}")
        else:
            print("    [SKIP] 未找到 gist_id.txt，跳过 Gist 更新")

    print(f"\n{'='*50}")
    print(f"  完成！APP 下次拉取配置将自动切换到:")
    print(f"  {new_url}")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()
