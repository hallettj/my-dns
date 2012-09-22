module Net.DNS ( DomainName
               , Message
               , Question
               , ResourceRecord
               , defaultMessage
               , RRType(RRType)
               , RRClass(RRClass)
               , RROpcode(RROpcode)
               , RRResponse(RRResponse)
               , putMessage ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
--import Data.ByteString.Parser (getWord16be, Parser)
import Data.Bits (Bits, shift)
import Data.Int (Int32)
import Data.List (foldl')
import Data.Serialize (decode, encode, put)
import Data.Serialize.Put (putWord16be, putWord32be, Put)
import Data.Word (Word8, Word16, Word32)
import Foreign.Marshal.Utils (fromBool, toBool)

type DomainName = String

data Message = Message { getId                :: Word16
                       , isResponse           :: Bool
                       , getMOpcode           :: RROpcode
                       , isAuthoritative      :: Bool
                       , isTruncated          :: Bool
                       , isRecursionDesired   :: Bool
                       , isRecursionAvailable :: Bool
                       , getZ                 :: Word8
                       , getMResponseCode     :: RRResponse
                       , getQuestions         :: [Question]
                       , getAnswers           :: [ResourceRecord]
                       , getAuthorities       :: [ResourceRecord]
                       , getAdditional        :: [ResourceRecord] }
               deriving (Eq, Show, Read)

data Question = Question { getQName :: DomainName
                         , getQType  :: RRType
                         , getQClass :: RRClass
                         }
                deriving (Eq, Show, Read)

data ResourceRecord = ResourceRecord { getRRName   :: DomainName
                                     , getRRType   :: RRType
                                     , getRRClass  :: RRClass
                                     , getTTL      :: Word32
                                     , getRDLength :: Word16
                                     , getRData    :: ByteString
                                     }
                      deriving (Eq, Show, Read)

defaultMessage = Message { getId                = 0
                         , isResponse           = True
                         , getMOpcode           = query
                         , isAuthoritative      = False
                         , isTruncated          = False
                         , isRecursionDesired   = False
                         , isRecursionAvailable = False
                         , getZ                 = 0
                         , getMResponseCode     = noError
                         , getQuestions         = []
                         , getAnswers           = []
                         , getAuthorities       = []
                         , getAdditional        = [] }

newtype RRType = RRType { getType :: Word16 } deriving (Eq, Show, Read)
a        = RRType 1   -- a host address
ns       = RRType 2   -- an authoritative name server
md       = RRType 3   -- a mail destination (Obsolete - use MX)
mf       = RRType 4   -- a mail forwarder (Obsolete - use MX)
cname    = RRType 5   -- the canonical name for an alias
soa      = RRType 6   -- marks the start of a zone of authority
mb       = RRType 7   -- a mailbox domain name (EXPERIMENTAL)
mg       = RRType 8   -- a mail group member (EXPERIMENTAL)
mr       = RRType 9   -- a mail rename domain name (EXPERIMENTAL)
null     = RRType 10  -- a null RR  -- (EXPERIMENTAL)
wks      = RRType 11  -- a well known service description
ptr      = RRType 12  -- a domain name pointer
hinfo    = RRType 13  -- host information
minfo    = RRType 14  -- mailbox or mail list information
mx       = RRType 15  -- mail exchange
txt      = RRType 16  -- text strings

newtype RRClass = RRClass { getClass :: Word16 } deriving (Eq, Show, Read)
internet = RRClass 1  -- the Internet
csnet    = RRClass 2  -- the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
chaos    = RRClass 3  -- the CHAOS class
hesiod   = RRClass 4  -- Hesiod [Dyer 87]

newtype RROpcode = RROpcode { getOpcode :: Word8 } deriving (Eq, Show, Read)
query    = RROpcode 0
iquery   = RROpcode 1
status   = RROpcode 2

newtype RRResponse = RRResponse { getResponseCode :: Word8 }
                     deriving (Eq, Show, Read)
noError        = RRResponse 0
formatError    = RRResponse 1
serverFailure  = RRResponse 2
nameError      = RRResponse 3
notImplemented = RRResponse 4
refused        = RRResponse 5

putMessage :: Message -> Put
putMessage msg = do
    putHeader msg
    mapM_ putQuestion       (getQuestions   msg)
    mapM_ putResourceRecord (getAnswers     msg)
    mapM_ putResourceRecord (getAuthorities msg)
    mapM_ putResourceRecord (getAdditional  msg)


-- The header contains the following fields:
-- 
--                                 1  1  1  1  1  1
--   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
-- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- |                      ID                       |
-- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
-- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- |                    QDCOUNT                    |
-- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- |                    ANCOUNT                    |
-- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- |                    NSCOUNT                    |
-- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- |                    ARCOUNT                    |
-- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

putHeader :: Message -> Put
putHeader msg = do
    putWord16be (getId msg)
    putWord16be (flags [
        (fromIntegral (fromBool        (isResponse           msg)), 1)
      , (fromIntegral (getOpcode       (getMOpcode           msg)), 4)
      , (fromIntegral (fromBool        (isAuthoritative      msg)), 1)
      , (fromIntegral (fromBool        (isTruncated          msg)), 1)
      , (fromIntegral (fromBool        (isRecursionDesired   msg)), 1)
      , (fromIntegral (fromBool        (isRecursionAvailable msg)), 1)
      , (fromIntegral (                (getZ                 msg)), 3)
      , (fromIntegral (getResponseCode (getMResponseCode     msg)), 4) ])
    putWord16be (fromIntegral (length (getQuestions   msg)))
    putWord16be (fromIntegral (length (getAnswers     msg)))
    putWord16be (fromIntegral (length (getAuthorities msg)))
    putWord16be (fromIntegral (length (getAdditional  msg)))

-- The first value in each tuple is the value of the flag, the second
-- value is the number of bits used to represent that value.
flags :: (Bits a) => [(a, Int)] -> a
flags = foldl' packFlag 0
    where packFlag packed (v, bits) = (packed `shift` bits) + v


-- The question section is used to carry the "question" in most queries,
-- i.e., the parameters that define what is being asked.  The section
-- contains QDCOUNT (usually 1) entries, each of the following format:
-- 
--                                     1  1  1  1  1  1
--       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
--     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--     |                                               |
--     /                     QNAME                     /
--     /                                               /
--     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--     |                     QTYPE                     |
--     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--     |                     QCLASS                    |
--     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

putQuestion :: Question -> Put
putQuestion q = do
    put           (getQName  q)
    putWord16be   (getType  (getQType  q))
    putWord16be   (getClass (getQClass q))


-- All RRs have the same top level format shown below:
-- 
--                                     1  1  1  1  1  1
--       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
--     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--     |                                               |
--     /                                               /
--     /                      NAME                     /
--     |                                               |
--     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--     |                      TYPE                     |
--     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--     |                     CLASS                     |
--     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--     |                      TTL                      |
--     |                                               |
--     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--     |                   RDLENGTH                    |
--     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
--     /                     RDATA                     /
--     /                                               /
--     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

putResourceRecord :: ResourceRecord -> Put
putResourceRecord rr = do
    put           (getRRName  rr)
    putWord16be   (getType  (getRRType  rr))
    putWord16be   (getClass (getRRClass rr))
    putWord32be   (getTTL   rr)
    putWord16be   (fromIntegral (B.length (getRData rr)))
    put           (getRData rr)



--parseMessage = do
--    id <- getWord16be
--    isResponse <- getBool
--               
--
--parseMessage :: ByteString -> Either String Message
--parseMessage msg = Message { getHeader = header
--                           , getQuestions = questions
--                           , getAnswers = answers
--                           , getAuthorities = authorities
--                           , getAdditional = additional
--                           }
--    where (header,      afterH)  = parseHeader msg
--          (questions,   afterQD) = parseQuestions (getQDCount header) afterH
--          (answers,     afterAN) = parseRRs (getANCount header) afterQD
--          (authorities, afterNS) = parseRRs (getNSCount header) afterAN
--          (additional,  _)       = parseRRs (getARCount header) afterNS
--
--parseHeader :: ByteString -> (Either String Header, ByteString)
--parseHeader msg = do
--    (id, rest) <- decode msg
--    (id, rest) <- parseWord msg
--
--parseWord :: ByteString -> (Either String Word16, ByteString)
--parseWord msg = getWord16be
