''' this is primarily for errors and exceptions '''

from xml.etree.ElementTree import fromstring as parse_xml, ParseError

#Error objects, Exceptions etc
#============================================================================
class EdgexException(Exception):
    """Base for exceptions returned by S3 servers"""
    @staticmethod
    def from_bytes(status, body):
        """
            extract the error from the xml response
        """
        if not body:
            raise RuntimeError("HTTP Error {}".format(status))
        try:
            xml = parse_xml(body)
        except ParseError:
            raise RuntimeError(body)
        code_el = xml.find("Code")
        if code_el is None or not code_el.text:
            raise RuntimeError(body)
        class_name = code_el.text
        try:
            cls = globals()[class_name]
        except KeyError:
            raise RuntimeError("Error {} is unknown".format(class_name))
        msg = xml.find("Message")
        return cls(class_name if msg is None else msg.text)

class AccessDenied(EdgexException):
    """Access is Denied"""
    pass
class AccountProblem(EdgexException):
    """Account has a problem"""
    pass
class AmbiguousGrantByEmailAddress(EdgexException):
    """ Grant looks Ambigious """
    pass
class BadDigest(EdgexException):
    """ Bad digest """
    pass
class BucketAlreadyExists(EdgexException):
    """ Bucket already exists  """
    pass
class BucketAlreadyOwnedByYou(EdgexException):
    """ Bucket is already owned by the same user """
    pass
class BucketNotEmpty(EdgexException):
    """ Bucket is not empty """
    pass
class CredentialsNotSupported(EdgexException):
    """ Credentials is not supported  """
    pass
class CrossLocationLoggingProhibited(EdgexException):
    """ Cross location logging is not allowed  """
    pass
class EntityTooSmall(EdgexException):
    """ Too small entity """
    pass
class EntityTooLarge(EdgexException):
    """ Too large entity  """
    pass
class ExpiredToken(EdgexException):
    """ Token has expired """
    pass
class IllegalVersioningConfigurationException(EdgexException):
    """ Version configuration is illegal """
    pass
class IncompleteBody(EdgexException):
    """ Incomplete body """
    pass
class IncorrectNumberOfFilesInPostRequest(EdgexException):
    """ Incorret number of files in the post request """
    pass
class InlineDataTooLarge(EdgexException):
    """ Inline data is too large """
    pass
class InternalError(EdgexException):
    """ Internal Error """
    pass
class InvalidAccessKeyId(EdgexException):
    """ Invalid Access  """
    pass
class InvalidAddressingHeader(EdgexException):
    """ Invalid Address header """
    pass
class InvalidArgument(EdgexException):
    """ Invalid Argument """
    pass
class InvalidBucketName(EdgexException):
    """ Invalid bucket name """
    pass
class InvalidBucketState(EdgexException):
    """ Invalid bucket state """
    pass
class InvalidDigest(EdgexException):
    """ Invalid digest """
    pass
class InvalidEncryptionAlgorithmError(EdgexException):
    """ Invalid encryption algorithm error """
    pass
class InvalidLocationConstraint(EdgexException):
    """ Invalid location constraint """
    pass
class InvalidObjectState(EdgexException):
    """ Invalid Object state """
    pass
class InvalidPart(EdgexException):
    """ Invalid part """
    pass
class InvalidPartOrder(EdgexException):
    """ Invalid part order """
    pass
class InvalidPayer(EdgexException):
    """ Invalid Player """
    pass
class InvalidPolicyDocument(EdgexException):
    """ Invalid policy """
    pass
class InvalidRange(EdgexException):
    """ Invalid range """
    pass
class InvalidRequest(EdgexException):
    """ Invalid request """
    pass
class InvalidSecurity(EdgexException):
    """ Invalid security """
    pass
class InvalidSOAPRequest(EdgexException):
    """ Invalid SOAP """
    pass
class InvalidStorageClass(EdgexException):
    """ Invalid Storage class """
    pass
class InvalidTargetBucketForLogging(EdgexException):
    """ Invalid target bucket """
    pass
class InvalidToken(EdgexException):
    """ Token is invalid """
    pass
class InvalidURI(EdgexException):
    """ URI is invalid """
    pass
class InvalidCommand(EdgexException):
    """ Command is invalid """
    pass
class InvalidStore(EdgexException):
    """ Store is invalid """
    pass
class InvalidDataBuffer(EdgexException):
    """ Buffer is invalid """
    pass
class KeyTooLong(EdgexException):
    """ Key is too long """
    pass
class MalformedACLError(EdgexException):
    """ACL is malformed  """
    pass
class MalformedPOSTRequest(EdgexException):
    """ POST request is malformed """
    pass
class MalformedXML(EdgexException):
    """ XML is malformed """
    pass
class MaxMessageLengthExceeded(EdgexException):
    """ Message length has exceeded the max """
    pass
class MaxPostPreDataLengthExceededError(EdgexException):
    """ POST predata length exceeded the error """
    pass
class MetadataTooLarge(EdgexException):
    """ Too large metadata """
    pass
class MethodNotAllowed(EdgexException):
    """ Method is not allowed """
    pass
class MissingAttachment(EdgexException):
    """ Attachment is missing  """
    pass
class MissingContentLength(EdgexException):
    """ COntent length is missing """
    pass
class MissingRequestBodyError(EdgexException):
    """ Request body is missing  """
    pass
class MissingSecurityElement(EdgexException):
    """ Security element is missing """
    pass
class MissingSecurityHeader(EdgexException):
    """ Secirity header is missing """
    pass
class NoLoggingStatusForKey(EdgexException):
    """ No logging status for this key """
    pass
class NoSuchBucket(EdgexException):
    """ No such bucket """
    pass
class NoSuchKey(EdgexException):
    """ No such key """
    pass
class NoSuchLifecycleConfiguration(EdgexException):
    """ No such life cycle configuration  """
    pass
class NoSuchUpload(EdgexException):
    """ No suck upload """
    pass
class NoSuchVersion(EdgexException):
    """ No such version  """
    pass
class NotSignedUp(EdgexException):
    """ Not signed up """
    pass
class NotSuchBucketPolicy(EdgexException):
    """ No such bucket """
    pass
class OperationAborted(EdgexException):
    """ Operation aborted """
    pass
class PermanentRedirect(EdgexException):
    """ Permanent redirect """
    pass
class PreconditionFailed(EdgexException):
    """ Precondition failed """
    pass
class Redirect(EdgexException):
    """ Redirect """
    pass
class RestoreAlreadyInProgress(EdgexException):
    """ Restore is already in progress """
    pass
class RequestIsNotMultiPartContent(EdgexException):
    """ Request is not multi-part content """
    pass
class RequestTimeout(EdgexException):
    """ Request timeout """
    pass
class RequestTimeTooSkewed(EdgexException):
    """ Request time is skewed """
    pass
class RequestTorrentOfBucketError(EdgexException):
    """ Request torrent bucket error """
    pass
class SignatureDoesNotMatch(EdgexException):
    """ Signature mis-match  """
    pass
class ServiceUnavailable(EdgexException):
    """ Service is unavailable """
    pass
class SlowDown(EdgexException):
    """ Slow down """
    pass
class TemporaryRedirect(EdgexException):
    """ Temporary redirect """
    pass
class TokenRefreshRequired(EdgexException):
    """ Token needs to be refreshed """
    pass
class TooManyBuckets(EdgexException):
    """ Too many buckets """
    pass
class UnexpectedContent(EdgexException):
    """ Unexpected content """
    pass
class UnresolvableGrantByEmailAddress(EdgexException):
    """ Unresolved Grant by email  """
    pass
class UserKeyMustBeSpecified(EdgexException):
    """ User key must be specified """
    pass
class EmptyTag(EdgexException):
    """ Tag is empty """
    pass
