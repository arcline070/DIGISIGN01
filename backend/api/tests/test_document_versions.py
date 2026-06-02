import json

from django.contrib.auth import get_user_model
from django.test import TestCase

from rest_framework.test import APIClient

from api.models import DocumentRecord


class DocumentVersionApiTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="alice", password="password123")
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_add_document_version_reuses_existing_document_id(self):
        first_resp = self.client.post(
            "/api/sign-document",
            {"data": "first revision", "document_id": "doc-1"},
            format="json",
        )

        self.assertEqual(first_resp.status_code, 200)
        first_payload = json.loads(first_resp.content.decode("utf-8"))
        self.assertEqual(first_payload["document_id"], "doc-1")
        self.assertEqual(first_payload["version_no"], "1")

        second_resp = self.client.post(
            "/api/add-document-version",
            {"data": "second revision", "document_id": "doc-1"},
            format="json",
        )

        self.assertEqual(second_resp.status_code, 200)
        second_payload = json.loads(second_resp.content.decode("utf-8"))
        self.assertEqual(second_payload["document_id"], "doc-1")
        self.assertEqual(second_payload["version_no"], "2")

        record = DocumentRecord.objects.get(doc_id="doc-1")
        self.assertEqual(record.versions.count(), 2)

    def test_my_document_ids_lists_current_users_records(self):
        self.client.post(
            "/api/sign-document",
            {"data": "alpha", "document_id": "alpha-doc"},
            format="json",
        )
        self.client.post(
            "/api/sign-document",
            {"data": "beta", "document_id": "beta-doc"},
            format="json",
        )

        resp = self.client.get("/api/my-document-ids")

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"document_ids": ["alpha-doc", "beta-doc"]})
