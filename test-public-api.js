#!/usr/bin/env node

const crypto = require('crypto')
const axios = require('axios')

// Test configuration
const BASE_URL = 'http://localhost:3000'
const PUBLIC_API_SECRET = 'test-secret-key-for-public-api'

/**
 * Generate HMAC-SHA256 signature
 */
function generateSignature(payload, timestamp, secret) {
  const data = JSON.stringify(payload) + timestamp
  return 'sha256=' + crypto.createHmac('sha256', secret).update(data).digest('hex')
}

/**
 * Test the public API generate-key endpoint
 */
async function testPublicApiGenerateKey() {
  try {
    console.log('🧪 Testing Public API Generate Key Endpoint...\n')

    const payload = {
      name: 'Test API Key',
      description: 'Generated via Public API for testing',
      expirationDays: 30,
      tokenLimit: 50000,
      dailyCostLimit: 10,
      monthlyCostLimit: 100,
      notifyFeishu: false // 不发送飞书通知，避免测试时发送无效消息
    }

    const timestamp = Date.now().toString()
    const signature = generateSignature(payload, timestamp, PUBLIC_API_SECRET)

    console.log('📊 Request Details:')
    console.log('URL:', `${BASE_URL}/public/api/generate-key`)
    console.log('Payload:', JSON.stringify(payload, null, 2))
    console.log('Timestamp:', timestamp)
    console.log('Signature:', signature)
    console.log('')

    const response = await axios.post(`${BASE_URL}/public/api/generate-key`, payload, {
      headers: {
        'Content-Type': 'application/json',
        'X-Signature': signature,
        'X-Timestamp': timestamp
      },
      timeout: 30000
    })

    console.log('✅ Response Status:', response.status)
    console.log('📊 Response Data:')
    console.log(JSON.stringify(response.data, null, 2))

    if (response.data.success && response.data.apiKey) {
      console.log('\n🎉 API Key generated successfully!')
      console.log('🔑 Generated API Key:', response.data.apiKey)
      console.log('📝 Key Info:')
      console.log('  - ID:', response.data.data.id)
      console.log('  - Name:', response.data.data.name)
      console.log('  - Token Limit:', response.data.data.tokenLimit?.toLocaleString())
      console.log('  - Daily Cost Limit: $' + response.data.data.dailyCostLimit)
      console.log('  - Monthly Cost Limit: $' + response.data.data.monthlyCostLimit)
      console.log('  - Expires At:', response.data.data.expiresAt)
      console.log('  - Status:', response.data.data.status)
    } else {
      console.error('❌ Failed to generate API key:', response.data)
    }

  } catch (error) {
    console.error('❌ Test Failed:')
    if (error.response) {
      console.error('Status:', error.response.status)
      console.error('Response:', error.response.data)
    } else {
      console.error('Error:', error.message)
    }
  }
}

/**
 * Test with Feishu notification
 */
async function testWithFeishuNotification() {
  try {
    console.log('\n\n🧪 Testing with Feishu Notification...\n')

    const payload = {
      name: 'Test API Key with Feishu',
      description: 'Testing Feishu notification functionality',
      expirationDays: 7,
      tokenLimit: 10000,
      dailyCostLimit: 5,
      monthlyCostLimit: 50,
      notifyFeishu: true,
      feishuWebhook: 'https://open.feishu.cn/open-apis/bot/v2/hook/test-webhook-url'
    }

    const timestamp = Date.now().toString()
    const signature = generateSignature(payload, timestamp, PUBLIC_API_SECRET)

    console.log('📊 Request Details:')
    console.log('Payload:', JSON.stringify(payload, null, 2))
    console.log('')

    const response = await axios.post(`${BASE_URL}/public/api/generate-key`, payload, {
      headers: {
        'Content-Type': 'application/json',
        'X-Signature': signature,
        'X-Timestamp': timestamp
      },
      timeout: 30000
    })

    console.log('✅ Response Status:', response.status)
    console.log('📊 Response Data:')
    console.log(JSON.stringify(response.data, null, 2))

  } catch (error) {
    console.error('❌ Test Failed:')
    if (error.response) {
      console.error('Status:', error.response.status)
      console.error('Response:', error.response.data)
    } else {
      console.error('Error:', error.message)
    }
  }
}

/**
 * Test invalid signature
 */
async function testInvalidSignature() {
  try {
    console.log('\n\n🧪 Testing Invalid Signature...\n')

    const payload = {
      name: 'Test Invalid Signature',
      description: 'This should fail due to invalid signature'
    }

    const timestamp = Date.now().toString()
    const invalidSignature = 'sha256=invalid-signature'

    const response = await axios.post(`${BASE_URL}/public/api/generate-key`, payload, {
      headers: {
        'Content-Type': 'application/json',
        'X-Signature': invalidSignature,
        'X-Timestamp': timestamp
      },
      timeout: 30000
    })

    console.log('❌ Unexpected success - signature validation should have failed')
    console.log('Response:', response.data)

  } catch (error) {
    if (error.response && error.response.status === 401) {
      console.log('✅ Correctly rejected invalid signature')
      console.log('Response:', error.response.data)
    } else {
      console.error('❌ Unexpected error:', error.message)
    }
  }
}

/**
 * Run all tests
 */
async function runTests() {
  console.log('🚀 Starting Public API Tests')
  console.log('=' .repeat(50))

  // Test 1: Basic API key generation
  await testPublicApiGenerateKey()

  // Test 2: Feishu notification (will likely fail due to invalid webhook, but should test the flow)
  await testWithFeishuNotification()

  // Test 3: Invalid signature
  await testInvalidSignature()

  console.log('\n' + '=' .repeat(50))
  console.log('🏁 Tests completed!')
  console.log('\n💡 Note: To enable the Public API, set these environment variables:')
  console.log('PUBLIC_API_ENABLED=true')
  console.log('PUBLIC_API_SECRET=test-secret-key-for-public-api')
  console.log('\nAnd restart the service.')
}

// Run tests if this file is executed directly
if (require.main === module) {
  runTests().catch(console.error)
}

module.exports = {
  testPublicApiGenerateKey,
  testWithFeishuNotification,
  testInvalidSignature,
  runTests
}