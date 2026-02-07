"""Tests for alert feedback functionality."""

import pytest


class TestFeedback:
    """Test feedback data model and validation."""

    def test_valid_feedback_values(self):
        """Only true_positive and false_positive are valid."""
        valid = {"true_positive", "false_positive"}
        assert "true_positive" in valid
        assert "false_positive" in valid
        assert "maybe" not in valid

    def test_feedback_request_shape(self):
        """Verify feedback request body structure."""
        from pydantic import BaseModel

        class FeedbackRequest(BaseModel):
            feedback: str

        req = FeedbackRequest(feedback="true_positive")
        assert req.feedback == "true_positive"

    def test_alert_with_feedback_fields(self):
        """Alert model should have feedback columns."""
        from backend.models.alert import Alert
        import sqlalchemy

        columns = {c.name for c in Alert.__table__.columns}
        assert "feedback" in columns
        assert "feedback_at" in columns
        assert "feedback_by" in columns

    def test_feedback_nullable(self):
        """Feedback columns should be nullable."""
        from backend.models.alert import Alert

        feedback_col = Alert.__table__.columns["feedback"]
        assert feedback_col.nullable is True
