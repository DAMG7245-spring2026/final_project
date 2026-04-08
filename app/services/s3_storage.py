"""AWS S3 storage service."""
import logging
from typing import Optional
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from app.config import get_settings

logger = logging.getLogger(__name__)


class S3Storage:
    """Service for AWS S3 document storage."""
    
    def __init__(self):
        self.settings = get_settings()
        self._client = None
    
    @property
    def client(self):
        """Lazy initialization of S3 client."""
        if self._client is None:
            self._client = boto3.client(
                "s3",
                aws_access_key_id=self.settings.aws_access_key_id,
                aws_secret_access_key=self.settings.aws_secret_access_key,
                region_name=self.settings.aws_region,
            )
        return self._client
    
    @property
    def bucket(self) -> str:
        """Get configured bucket name."""
        return self.settings.s3_bucket
    
    async def health_check(self) -> tuple[bool, Optional[str]]:
        """Check if S3 connection is healthy."""
        try:
            self.client.head_bucket(Bucket=self.bucket)
            return True, None
        except NoCredentialsError:
            return False, "No AWS credentials configured"
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "404":
                return False, f"Bucket '{self.bucket}' not found"
            return False, str(e)
        except Exception as e:
            return False, str(e)
    
    def upload_document(
        self, 
        key: str, 
        content: bytes, 
        content_type: str = "application/octet-stream",
        metadata: Optional[dict] = None
    ) -> bool:
        """Upload a document to S3."""
        try:
            extra_args = {"ContentType": content_type}
            if metadata:
                extra_args["Metadata"] = metadata
            
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=content,
                **extra_args
            )
            logger.info(f"Uploaded document: {key}")
            return True
        except Exception as e:
            logger.error(f"Failed to upload {key}: {e}")
            return False
    
    def download_document(self, key: str) -> Optional[bytes]:
        """Download a document from S3."""
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=key)
            return response["Body"].read()
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                logger.warning(f"Document not found: {key}")
            else:
                logger.error(f"Failed to download {key}: {e}")
            return None
    
    def delete_document(self, key: str) -> bool:
        """Delete a document from S3."""
        try:
            self.client.delete_object(Bucket=self.bucket, Key=key)
            logger.info(f"Deleted document: {key}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete {key}: {e}")
            return False
    
    def list_documents(self, prefix: str = "") -> list[str]:
        """List documents with optional prefix filter."""
        try:
            response = self.client.list_objects_v2(
                Bucket=self.bucket,
                Prefix=prefix
            )
            return [obj["Key"] for obj in response.get("Contents", [])]
        except Exception as e:
            logger.error(f"Failed to list documents: {e}")
            return []
    
    def generate_presigned_url(
        self, 
        key: str, 
        expiration: int = 3600
    ) -> Optional[str]:
        """Generate a presigned URL for document access."""
        try:
            url = self.client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket, "Key": key},
                ExpiresIn=expiration
            )
            return url
        except Exception as e:
            logger.error(f"Failed to generate presigned URL for {key}: {e}")
            return None


# Singleton instance
_s3_storage: Optional[S3Storage] = None


def get_s3_storage() -> S3Storage:
    """Get or create S3 storage singleton."""
    global _s3_storage
    if _s3_storage is None:
        _s3_storage = S3Storage()
    return _s3_storage