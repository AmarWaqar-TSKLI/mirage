"""S3 XML response serializers formatted for AWS CLI and SDK compatibility."""

from typing import List
from xml.sax.saxutils import escape
from .storage import S3Object


def xml_list_buckets(buckets: List[str]) -> str:
    xml = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">',
        '  <Owner>',
        '    <ID>0123456789abcdef</ID>',
        '    <DisplayName>infra-ops</DisplayName>',
        '  </Owner>',
        '  <Buckets>',
    ]
    for b in buckets:
        xml.append('    <Bucket>')
        xml.append(f'      <Name>{escape(b)}</Name>')
        xml.append('      <CreationDate>2026-01-15T08:00:00.000Z</CreationDate>')
        xml.append('    </Bucket>')
    xml.extend([
        '  </Buckets>',
        '</ListAllMyBucketsResult>',
    ])
    return "\n".join(xml)


def xml_list_objects(bucket: str, objects: List[S3Object], prefix: str = "") -> str:
    xml = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">',
        f'  <Name>{escape(bucket)}</Name>',
        f'  <Prefix>{escape(prefix)}</Prefix>',
        f'  <KeyCount>{len(objects)}</KeyCount>',
        '  <MaxKeys>1000</MaxKeys>',
        '  <IsTruncated>false</IsTruncated>',
    ]
    for obj in objects:
        ts = obj.last_modified.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        xml.extend([
            '  <Contents>',
            f'    <Key>{escape(obj.key)}</Key>',
            f'    <LastModified>{ts}</LastModified>',
            f'    <ETag>{escape(obj.etag)}</ETag>',
            f'    <Size>{len(obj.data)}</Size>',
            '    <StorageClass>STANDARD</StorageClass>',
            '  </Contents>',
        ])
    xml.append('</ListBucketResult>')
    return "\n".join(xml)


def xml_error(code: str, message: str, resource: str = "") -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Error>\n'
        f'  <Code>{escape(code)}</Code>\n'
        f'  <Message>{escape(message)}</Message>\n'
        f'  <Resource>{escape(resource)}</Resource>\n'
        '  <RequestId>TX000000000000000001</RequestId>\n'
        '</Error>'
    )
