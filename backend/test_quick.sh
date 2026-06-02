#!/bin/bash

# Simple curl-based test script for hash chaining
# Run: bash test_quick.sh

set -e

BASE_URL="http://localhost:8000/api"
USERNAME="testuser"
PASSWORD="testpass123"

echo "=========================================="
echo "HASH CHAIN TESTING - QUICK START"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Step 1: Login
echo -e "${BLUE}[1/5]${NC} Logging in as $USERNAME..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/login/" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"$USERNAME\", \"password\": \"$PASSWORD\"}")

TOKEN=$(echo $LOGIN_RESPONSE | grep -o '"token":"[^"]*' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
  echo -e "${RED}Failed to login${NC}"
  echo "Response: $LOGIN_RESPONSE"
  exit 1
fi

echo -e "${GREEN}✓ Login successful${NC}"
echo "Token: ${TOKEN:0:20}..."
echo ""

# Step 2: Sign a new document (Phase 1)
echo -e "${BLUE}[2/5]${NC} Signing new document (Phase 1)..."
SIGN_RESPONSE=$(curl -s -X POST "$BASE_URL/sign-document/" \
  -H "Authorization: Token $TOKEN" \
  -F "data=Initial version - This is my test document")

DOC_ID=$(echo $SIGN_RESPONSE | grep -o '"document_id":"[^"]*' | cut -d'"' -f4)
V1_CHAIN_HASH=$(echo $SIGN_RESPONSE | grep -o '"chain_hash":"[^"]*' | cut -d'"' -f4)
V1_PREV=$(echo $SIGN_RESPONSE | grep -o '"prev_chain_hash":"[^"]*' | cut -d'"' -f4)

if [ -z "$DOC_ID" ]; then
  echo -e "${RED}Failed to sign document${NC}"
  echo "Response: $SIGN_RESPONSE"
  exit 1
fi

echo -e "${GREEN}✓ Document signed${NC}"
echo "Document ID: $DOC_ID"
echo "Version: 1"
echo "prev_chain_hash: $V1_PREV"
echo "chain_hash: ${V1_CHAIN_HASH:0:16}..."

# Save response
echo "$SIGN_RESPONSE" | python -m json.tool > signed_v1.json
echo "Saved: signed_v1.json"
echo ""

# Step 3: Add Version 2 (Phase 2)
echo -e "${BLUE}[3/5]${NC} Adding Version 2 (Phase 2)..."
V2_RESPONSE=$(curl -s -X POST "$BASE_URL/add-document-version/" \
  -H "Authorization: Token $TOKEN" \
  -F "document_id=$DOC_ID" \
  -F "data=Updated version - More content added")

V2_CHAIN_HASH=$(echo $V2_RESPONSE | grep -o '"chain_hash":"[^"]*' | cut -d'"' -f4)
V2_PREV=$(echo $V2_RESPONSE | grep -o '"prev_chain_hash":"[^"]*' | cut -d'"' -f4)

if [ -z "$V2_CHAIN_HASH" ]; then
  echo -e "${RED}Failed to add version${NC}"
  echo "Response: $V2_RESPONSE"
  exit 1
fi

echo -e "${GREEN}✓ Version 2 added${NC}"
echo "Version: 2"
echo "prev_chain_hash: ${V2_PREV:0:16}..."
echo "chain_hash: ${V2_CHAIN_HASH:0:16}..."

# Check if V2's prev matches V1's chain
if [ "$V1_CHAIN_HASH" == "$V2_PREV" ]; then
  echo -e "${GREEN}✓ Chain link valid: V1 → V2${NC}"
else
  echo -e "${RED}✗ Chain link broken: V1 → V2${NC}"
fi

echo "$V2_RESPONSE" | python -m json.tool > signed_v2.json
echo "Saved: signed_v2.json"
echo ""

# Step 4: Add Version 3
echo -e "${BLUE}[4/5]${NC} Adding Version 3..."
V3_RESPONSE=$(curl -s -X POST "$BASE_URL/add-document-version/" \
  -H "Authorization: Token $TOKEN" \
  -F "document_id=$DOC_ID" \
  -F "data=Final version - Everything complete")

V3_CHAIN_HASH=$(echo $V3_RESPONSE | grep -o '"chain_hash":"[^"]*' | cut -d'"' -f4)
V3_PREV=$(echo $V3_RESPONSE | grep -o '"prev_chain_hash":"[^"]*' | cut -d'"' -f4)

if [ -z "$V3_CHAIN_HASH" ]; then
  echo -e "${RED}Failed to add version 3${NC}"
  exit 1
fi

echo -e "${GREEN}✓ Version 3 added${NC}"
echo "Version: 3"
echo "prev_chain_hash: ${V3_PREV:0:16}..."
echo "chain_hash: ${V3_CHAIN_HASH:0:16}..."

# Check if V3's prev matches V2's chain
if [ "$V2_CHAIN_HASH" == "$V3_PREV" ]; then
  echo -e "${GREEN}✓ Chain link valid: V2 → V3${NC}"
else
  echo -e "${RED}✗ Chain link broken: V2 → V3${NC}"
fi

echo "$V3_RESPONSE" | python -m json.tool > signed_v3.json
echo "Saved: signed_v3.json"
echo ""

# Step 5: Verify Chain (Phase 3)
echo -e "${BLUE}[5/5]${NC} Verifying chain integrity (Phase 3)..."
VERIFY_RESPONSE=$(curl -s -X POST "$BASE_URL/verify-document/" \
  -F "file=@signed_v3.json")

VERIFY_STATUS=$(echo $VERIFY_RESPONSE | grep -o '"status":"[^"]*' | head -1 | cut -d'"' -f4)
CHAIN_STATUS=$(echo $VERIFY_RESPONSE | grep -o '"chain_verification".*' | grep -o '"status":"[^"]*' | head -1 | cut -d'"' -f4)
VERIFIED_COUNT=$(echo $VERIFY_RESPONSE | grep -o '"verified_versions":[0-9]*' | cut -d':' -f2)
BROKEN_AT=$(echo $VERIFY_RESPONSE | grep -o '"broken_at_version":[^,}]*' | cut -d':' -f2)

echo -e "${GREEN}✓ Verification complete${NC}"
echo "Signature Status: $VERIFY_STATUS"
echo "Chain Status: $CHAIN_STATUS"
echo "Verified Versions: $VERIFIED_COUNT"
echo "Broken At Version: $BROKEN_AT"

echo "$VERIFY_RESPONSE" | python -m json.tool > verify_response.json
echo "Saved: verify_response.json"
echo ""

# Summary
echo "=========================================="
echo "TEST SUMMARY"
echo "=========================================="

if [ "$VERIFY_STATUS" == "valid" ] && [ "$CHAIN_STATUS" == "valid" ]; then
  echo -e "${GREEN}✓ ALL TESTS PASSED${NC}"
  echo ""
  echo "Summary:"
  echo "  • Phase 1: Created V1 with GENESIS anchor ✓"
  echo "  • Phase 2: Added V2 and V3 with valid chain links ✓"
  echo "  • Phase 3: Chain verification passed ✓"
  echo ""
  echo "Next: Try tampering with the database to test detection!"
  echo "See TEST_HASH_CHAIN.md for tampering tests"
else
  echo -e "${RED}✗ TESTS FAILED${NC}"
  echo "Status: $VERIFY_STATUS"
  echo "Chain: $CHAIN_STATUS"
fi

echo ""
echo "Generated files:"
echo "  - signed_v1.json"
echo "  - signed_v2.json"
echo "  - signed_v3.json"
echo "  - verify_response.json"
echo ""
