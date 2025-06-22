---
title: 记录Coding托管代码的本地备份
typora-root-url: coding-backup-record
date: 2025-06-22 10:52:19
tags:
- coding
- backup
categories: Misc
---

# 记录Coding托管代码的本地备份

由于Coding订阅策略的调整，免费版将于2025年9月1日无法登录。然而大量代码仅存在于云端，需要备份到本地，故记录一次代码的备份过程。

代码决定使用CODING API+git工具克隆。

## 访问令牌

在团队中，个人账户设置，访问令牌，新建访问令牌

权限选择`用户信息-只读`，`团队信息-只读`，`项目信息-只读`，`代码仓库-只读`即可。

CODING API文档：[https://coding.net/help/openapi#/](https://coding.net/help/openapi#/)

## 脚本

需要团队管理员权限

```python
import requests
import os

base_url = "https://e.coding.net/open-api/"
sourceFolderName = "SourceDownloaded"
headers = {
    "Authorization": "Token ***********************",
    "Content-Type": "application/json",
    "Accept": "application/json"
}
payload = {
    "PageNumber": "1",
    "PageSize": "50"
}

# 切换到新的目录中，不要在同目录下拉屎
if not os.path.exists(sourceFolderName):
    os.mkdir(sourceFolderName)
os.chdir(sourceFolderName)
# 查询所有项目
querystring = {"Action":"DescribeCodingProjects"}
response = requests.post(base_url, json=payload, headers=headers, params=querystring)
projectList = response.json()['Response']['Data']['ProjectList']

# 查询项目下代码仓库
for i in range(len(projectList)):
    singleProject = projectList[i]

    # 依据项目名称新建文件夹，并切换到新的文件夹中
    repoName = singleProject['DisplayName']
    os.mkdir(repoName)
    os.chdir(repoName)

    # 写入一些项目的信息
    infoFile = os.open('ProjectInfo.txt', os.O_CREAT | os.O_RDWR)
    os.write(infoFile, str(repoName + "\n" + singleProject['Description'] + "\n" + str(singleProject['CreatedAt'])).encode())
    os.close(infoFile)

    # 保存图标
    iconUrl = singleProject['Icon']
    r = requests.get(iconUrl)
    with open('icon', 'wb') as f:
        f.write(r.content)

    # 获取项目中代码仓库信息，主要是git地址
    querystring = {"Action":"DescribeProjectDepotInfoList","action":"DescribeProjectDepotInfoList"}
    payload = {
        "PageNumber": "1",
        "PageSize": "100",
        "ProjectId": projectList[i]['Id']
    }
    r = requests.post(base_url, json=payload, headers=headers, params=querystring)
    # 获取项目下代码仓库，并克隆到本地
    depots = r.json()['Response']['DepotData']['Depots']
    for j in range(len(depots)):
        depot = depots[j]
        # 创建代码仓库目录
        name = depot['Name']
        os.mkdir(name)
        os.chdir(name)

        # 写入一些代码仓库的信息
        infoFile = os.open('DepotInfo.txt', os.O_CREAT | os.O_RDWR)
        os.write(infoFile, str(name + "\n" + depot['Description'] + "\n" + str(depot['CreatedAt'])).encode())
        os.close(infoFile)

        # 克隆所有分支
        url = depot['HttpsUrl']
        os.system("git clone --mirror " + url + " .git")
        os.system("git config --bool core.bare false")
        os.system("git reset --hard")
        os.chdir("..")

    # 返回上一级项目总文件夹
    os.chdir('..')
        
```

脚本获取了团队下所有项目，并逐项目获取其代码仓库，并将代码仓库中代码利用git工具克隆到本地。脚本还获取了项目的图标（存为项目文件夹下`icon`文件）、描述、创建时间（存于项目文件夹下`ProjectInfo.txt`文件），并获取了代码仓库的描述、创建时间（代码仓库文件夹下`DepotInfo.txt`文件）。

项目获取数设为50，单个项目下的获取代码仓库数为100，未考虑更多数量的情况。

（完）
