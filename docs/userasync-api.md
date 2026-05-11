# 用户同步 API 说明书

## 概述

用户同步接口用于将rbac模块中的单个或批量用户同步到dapi模块，并为每个用户生成API Key。同步后的用户可以使用该API Key调用dapi模块提供的服务。

## 接口信息

| 项目 | 值 |
|------|-----|
| 接口地址 | `/rbac/usersync/` |
| 请求方法 | POST |
| Content-Type | application/json |
| 认证方式 | 需要用户登录session |

## 请求参数

### 公共参数

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| action | string | 是 | 操作类型：`single`（单个用户）或 `batch`（批量用户） |
| dappid | string | 是 | dapi应用ID，标识哪个应用要同步用户 |

### 单个用户同步参数（action=single）

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| user | object | 是 | 用户信息对象 |
| user.id | string | 是 | rbac用户ID |
| user.orgid | string | 是 | 用户所属机构ID |
| user.username | string | 否 | 用户名 |
| user.name | string | 否 | 用户姓名 |
| user.email | string | 否 | 用户邮箱 |
| user.phone | string | 否 | 用户手机号 |

### 批量用户同步参数（action=batch）

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| users | array | 是 | 用户信息对象数组 |
| users[].id | string | 是 | rbac用户ID |
| users[].orgid | string | 是 | 用户所属机构ID |
| users[].username | string | 否 | 用户名 |
| users[].name | string | 否 | 用户姓名 |
| users[].email | string | 否 | 用户邮箱 |
| users[].phone | string | 否 | 用户手机号 |

## 请求示例

### 单个用户同步

```json
POST /rbac/userasync/
Content-Type: application/json

{
    "action": "single",
    "dappid": "myapp",
    "user": {
        "id": "u123456789",
        "orgid": "org987654321",
        "username": "testuser",
        "name": "测试用户",
        "email": "test@example.com"
    }
}
```

### 批量用户同步

```json
POST /rbac/userasync/
Content-Type: application/json

{
    "action": "batch",
    "dappid": "myapp",
    "users": [
        {
            "id": "u001",
            "orgid": "org001",
            "username": "user1",
            "name": "用户一"
        },
        {
            "id": "u002",
            "orgid": "org001",
            "username": "user2",
            "name": "用户二"
        }
    ]
}
```

## 响应格式

### 成功响应

#### 单个用户

```json
{
    "status": "success",
    "apikey": "生成的apikey值",
    "user_id": "u123456789",
    "message": "apikey创建成功"
}
```

#### 批量用户

```json
{
    "status": "success",
    "data": [
        {
            "user_id": "u001",
            "username": "user1",
            "apikey": "apikey值1",
            "status": "created",
            "result_status": "success"
        },
        {
            "user_id": "u002",
            "username": "user2",
            "apikey": "apikey值2",
            "status": "existing",
            "result_status": "success"
        }
    ],
    "total": 2
}
```

### 错误响应

```json
{
    "status": "error",
    "message": "错误描述信息"
}
```

## 状态字段说明

| 状态值 | 说明 |
|--------|------|
| created | 新创建的apikey |
| existing | 用户apikey已存在，返回现有值 |
| error | 处理失败（仅批量模式单个用户可能出现） |

## 错误码

| HTTP状态码 | 错误信息 | 说明 |
|-----------|----------|------|
| 200 | dappid参数必填 | 未提供dappid参数 |
| 200 | user.id和user.orgid参数必填 | 单个用户模式下缺少必填字段 |
| 200 | users参数必填（用户对象数组） | 批量模式下users为空 |
| 200 | user.id和user.orgid必填 | 批量模式下某个用户缺少必填字段 |
| 200 | action参数必须是single或batch | action值无效 |
| 200 | 创建apikey失败: xxx | 数据库操作异常 |

## 实现说明

### 工作流程

1. 接口接收POST请求，解析参数
2. 验证必需参数（dappid、user_id、orgid）
3. 检查dapi模块是否提供了`create_user_apikey`函数
   - 如果存在，调用该函数处理
   - 如果不存在，使用fallback逻辑直接创建apikey
4. 检查`downapikey`表中是否已存在该用户的apikey
   - 已存在：返回现有apikey（解码后）
   - 不存在：创建新apikey并返回
5. 返回JSON格式结果

### 数据库表

接口操作`downapikey`表（dapi模块）：

| 字段 | 类型 | 说明 |
|------|------|------|
| id | varchar(32) | 主键 |
| dappid | varchar(200) | dapi应用ID |
| dorgid | varchar(200) | 外部机构ID |
| duserid | varchar(32) | 外部用户ID（rbac用户ID） |
| orgid | varchar(200) | 内部机构ID |
| userid | varchar(32) | 内部用户ID |
| apikey | varchar(4000) | API密钥（加密存储） |
| enabled | varchar(1) | 是否启用 |
| created_at | date | 创建日期 |
| expires_at | date | 过期日期 |

### 依赖函数

接口使用以下ServerEnv注册的函数：

| 函数名 | 来源模块 | 说明 |
|--------|----------|------|
| get_module_dbname | appbase | 获取模块数据库名 |
| getID | apppublic | 生成唯一ID |
| password_encode | appbase | 加密字符串 |
| password_decode | appbase | 解密字符串 |
| create_user_apikey | dapi | 创建用户apikey（可选） |

## 调用示例

### curl

```bash
# 单个用户同步
curl -X POST http://localhost:8000/rbac/usersync/ \
  -H "Content-Type: application/json" \
  -H "Cookie: session_id=xxx" \
  -d '{
    "action": "single",
    "dappid": "myapp",
    "user": {
      "id": "u123",
      "orgid": "org456",
      "username": "testuser"
    }
  }'

# 批量用户同步
curl -X POST http://localhost:8000/rbac/usersync/ \
  -H "Content-Type: application/json" \
  -H "Cookie: session_id=xxx" \
  -d '{
    "action": "batch",
    "dappid": "myapp",
    "users": [
      {"id": "u001", "orgid": "org001", "username": "user1"},
      {"id": "u002", "orgid": "org001", "username": "user2"}
    ]
  }'
```

### Python

```python
import requests

# 单个用户同步
response = requests.post(
    'http://localhost:8000/rbac/usersync/',
    cookies={'session_id': 'xxx'},
    json={
        'action': 'single',
        'dappid': 'myapp',
        'user': {
            'id': 'u123',
            'orgid': 'org456',
            'username': 'testuser'
        }
    }
)
print(response.json())

# 批量用户同步
response = requests.post(
    'http://localhost:8000/rbac/usersync/',
    cookies={'session_id': 'xxx'},
    json={
        'action': 'batch',
        'dappid': 'myapp',
        'users': [
            {'id': 'u001', 'orgid': 'org001', 'username': 'user1'},
            {'id': 'u002', 'orgid': 'org001', 'username': 'user2'}
        ]
    }
)
print(response.json())
```

## 注意事项

1. **认证要求**：接口需要有效的用户登录session，未登录用户无法调用
2. **幂等性**：同一用户多次同步不会创建多个apikey，会返回已存在的apikey
3. **批量处理**：批量模式下每个用户独立处理，某个用户失败不影响其他用户
4. **安全存储**：apikey在数据库中使用password_encode加密存储，返回时自动解密
5. **有效期**：创建的apikey默认有效期至9999-12-31
6. **字段扩展**：user对象可包含users表的任意字段，会作为**kwargs传递给create_user_apikey函数
