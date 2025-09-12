const express = require('express')
const router = express.Router()
const crypto = require('crypto')
const apiKeyService = require('../services/apiKeyService')
const webhookService = require('../services/webhookService')
const logger = require('../utils/logger')
const { getISOStringWithTimezone } = require('../utils/dateHelper')

// 根路径路由
router.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Claude Relay Service Public API',
    version: '1.0.0',
    endpoints: ['GET /public/test', 'GET /public/api/test', 'POST /public/api/generate-key'],
    timestamp: new Date().toISOString()
  })
})

// API路径根路由
router.get('/api/', (req, res) => {
  res.json({
    success: true,
    message: 'Public API endpoints',
    endpoints: ['GET /public/api/test', 'POST /public/api/generate-key'],
    timestamp: new Date().toISOString()
  })
})

// Test route to verify routes are working
router.get('/test', (req, res) => {
  res.json({
    success: true,
    message: 'Public API routes are working',
    timestamp: new Date().toISOString()
  })
})

// Test route at API path level
router.get('/api/test', (req, res) => {
  res.json({
    success: true,
    message: 'API path level test route is working',
    timestamp: new Date().toISOString()
  })
})

// IP白名单中间件
const ipWhitelistMiddleware = (req, res, next) => {
  const clientIp = req.ip || req.connection.remoteAddress
  const config = require('../../config/config')

  if (!config.publicApi?.enabled) {
    return res.status(403).json({
      success: false,
      error: 'Public API is disabled'
    })
  }

  const allowedIPs = config.publicApi.allowedIPs || []
  if (allowedIPs.length > 0 && !allowedIPs.includes(clientIp)) {
    logger.warn(`Unauthorized IP access attempt: ${clientIp}`)
    return res.status(403).json({
      success: false,
      error: 'IP not allowed'
    })
  }

  next()
}

// 签名验证中间件
const signatureMiddleware = (req, res, next) => {
  const config = require('../../config/config')
  const signature = req.headers['x-signature']
  const timestamp = req.headers['x-timestamp']

  if (!signature || !timestamp) {
    return res.status(401).json({
      success: false,
      error: 'Missing signature or timestamp'
    })
  }

  // 检查时间戳（防重放攻击）
  const now = Date.now()
  const requestTime = parseInt(timestamp)
  if (Math.abs(now - requestTime) > 300000) {
    // 5分钟时间窗口
    return res.status(401).json({
      success: false,
      error: 'Request timestamp too old or invalid'
    })
  }

  // 验证签名
  const { secret } = config.publicApi
  const payload = JSON.stringify(req.body) + timestamp
  const expectedSignature = crypto.createHmac('sha256', secret).update(payload).digest('hex')

  if (signature !== `sha256=${expectedSignature}`) {
    logger.warn('Invalid signature in public API request')
    return res.status(401).json({
      success: false,
      error: 'Invalid signature'
    })
  }

  next()
}

/**
 * POST /public/api/generate-key
 * 生成API Key的公开端点
 *
 * Request Body:
 * {
 *   "name": "API Key名称",
 *   "description": "描述信息",
 *   "expirationDays": 30,
 *   "tokenLimit": 10000,
 *   "dailyCostLimit": 100,
 *   "monthlyCostLimit": 1000,
 *   "notifyFeishu": true,
 *   "feishuWebhook": "https://open.feishu.cn/open-apis/bot/v2/hook/xxx"
 * }
 */
router.post('/api/generate-key', ipWhitelistMiddleware, signatureMiddleware, async (req, res) => {
  try {
    const {
      name,
      description,
      expirationDays = 30,
      tokenLimit,
      dailyCostLimit,
      monthlyCostLimit,
      notifyFeishu = true,
      feishuWebhook
    } = req.body

    // 参数验证
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Name is required and must be a non-empty string'
      })
    }

    if (tokenLimit && (typeof tokenLimit !== 'number' || tokenLimit <= 0)) {
      return res.status(400).json({
        success: false,
        error: 'Token limit must be a positive number'
      })
    }

    if (dailyCostLimit && (typeof dailyCostLimit !== 'number' || dailyCostLimit <= 0)) {
      return res.status(400).json({
        success: false,
        error: 'Daily cost limit must be a positive number'
      })
    }

    if (monthlyCostLimit && (typeof monthlyCostLimit !== 'number' || monthlyCostLimit <= 0)) {
      return res.status(400).json({
        success: false,
        error: 'Monthly cost limit must be a positive number'
      })
    }

    // 计算过期时间
    let expiresAt = null
    if (expirationDays && expirationDays > 0) {
      expiresAt = new Date()
      expiresAt.setDate(expiresAt.getDate() + expirationDays)
    }

    // 生成API Key
    const apiKeyOptions = {
      name: name.trim(),
      description: description?.trim() || '',
      tokenLimit,
      expiresAt,
      dailyCostLimit,
      monthlyCostLimit,
      createdBy: 'public-api',
      activationMode: 'immediate'
    }

    const apiKeyResult = await apiKeyService.generateApiKey(apiKeyOptions)

    if (!apiKeyResult || !apiKeyResult.apiKey) {
      return res.status(500).json({
        success: false,
        error: 'Failed to generate API key'
      })
    }

    const { apiKey, ...keyInfo } = apiKeyResult

    logger.info(`Public API generated new API key: ${keyInfo.id}`)

    // 发送飞书通知
    if (notifyFeishu) {
      try {
        await sendApiKeyCreatedNotification({
          apiKey,
          keyInfo,
          feishuWebhook
        })
      } catch (notifyError) {
        logger.error('Failed to send Feishu notification for API key creation:', notifyError)
        // 不因通知失败而影响API Key创建成功
      }
    }

    // 返回成功结果（不包含完整API Key）
    res.json({
      success: true,
      data: {
        id: keyInfo.id,
        name: keyInfo.name,
        description: keyInfo.description,
        keyPrefix: `${apiKey.substring(0, 8)}...`,
        tokenLimit: keyInfo.tokenLimit,
        dailyCostLimit: keyInfo.dailyCostLimit,
        monthlyCostLimit: keyInfo.monthlyCostLimit,
        expiresAt: keyInfo.expiresAt,
        createdAt: keyInfo.createdAt,
        status: keyInfo.status
      },
      apiKey // 完整的API Key只在创建时返回一次
    })
  } catch (error) {
    logger.error('Error in public API generate-key:', error)
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    })
  }
})

/**
 * 发送API Key创建成功的飞书通知
 */
async function sendApiKeyCreatedNotification({ apiKey, keyInfo, feishuWebhook }) {
  try {
    // 扩展 webhookService 发送通知
    await webhookService.sendNotification('apiKeyCreated', {
      apiKeyId: keyInfo.id,
      apiKeyName: keyInfo.name,
      apiKey,
      keyPrefix: `${apiKey.substring(0, 8)}...`,
      description: keyInfo.description,
      tokenLimit: keyInfo.tokenLimit,
      dailyCostLimit: keyInfo.dailyCostLimit,
      monthlyCostLimit: keyInfo.monthlyCostLimit,
      expiresAt: keyInfo.expiresAt,
      createdAt: keyInfo.createdAt,
      timestamp: getISOStringWithTimezone(new Date()),
      customWebhook: feishuWebhook
    })

    logger.info(`Sent Feishu notification for API key creation: ${keyInfo.id}`)
  } catch (error) {
    logger.error('Failed to send API key creation notification:', error)
    throw error
  }
}

module.exports = router
