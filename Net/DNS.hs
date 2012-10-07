module Net.DNS ( DomainName
               , domainName
               , fromDomainName
               , Message
               , Question(..)
               , ResourceRecord(..)
               , defaultMessage
               , RRType(..)
               , RRClass(..)
               , Opcode(..)
               , ResponseCode(..)

               -- message constructor field names
               , getId
               , isResponse
               , getOpcode
               , isAuthoritative
               , isTruncated
               , isRecursionDesired
               , isRecursionAvailable
               , getZ
               , getResponseCode
               , getQuestions
               , getAnswers
               , getAuthorities
               , getAdditional

               ---- question constructor field names
               --, getQName
               --, getQType
               --, getQClass

               ---- resource record constructor field names
               --, getRRName
               --, getRRType
               --, getRRClass
               --, getTTL
               --, getRRData

               -- resource record types
               , a
               , ns
               , md
               , mf
               , cname
               , soa
               , mb
               , mg
               , mr
               , null
               , wks
               , ptr
               , hinfo
               , minfo
               , mx
               , txt

               -- resource record classes
               , internet
               , csnet
               , chaos
               , hesiod

               -- message opcodes
               , query
               , iquery
               , status

               -- response codes
               , noError
               , formatError
               , serverFailure
               , nameError
               , notImplemented
               , refused ) where

import Control.Monad (liftM, replicateM)
import Data.ByteString (ByteString)
import Data.ByteString.UTF8 (fromString, toString)
import qualified Data.ByteString as B
import Data.Bits ((.&.), Bits, complement, shiftL, shiftR)
import Data.List (foldl', intercalate, null)
import Data.List.Split (splitOn)
import Data.Serialize (get, put, Serialize)
import Data.Serialize.Get (getBytes, getWord8, getWord16be, getWord32be)
import Data.Serialize.Put (putByteString, putWord8, putWord16be, putWord32be, Putter)
import Data.Word (Word8, Word16, Word32)
import Foreign.Marshal.Utils (fromBool, toBool)
import Prelude hiding (null)

newtype DomainName = DomainName [String] deriving (Eq, Show, Read)

domainName :: String -> DomainName
domainName = DomainName . labels
    where labels = filter (not . null) . splitOn "."

fromDomainName :: DomainName -> String
fromDomainName (DomainName n) = intercalate "." n ++ "."

data Message = Message { getId                :: Word16
                       , isResponse           :: Bool
                       , getOpcode            :: Opcode
                       , isAuthoritative      :: Bool
                       , isTruncated          :: Bool
                       , isRecursionDesired   :: Bool
                       , isRecursionAvailable :: Bool
                       , getZ                 :: Word8
                       , getResponseCode      :: ResponseCode
                       , getQuestions         :: [Question]
                       , getAnswers           :: [ResourceRecord]
                       , getAuthorities       :: [ResourceRecord]
                       , getAdditional        :: [ResourceRecord] }
               deriving (Eq, Show, Read)

data Question = Question { getQName  :: DomainName
                         , getQType  :: RRType
                         , getQClass :: RRClass
                         }
                deriving (Eq, Show, Read)

data ResourceRecord = ResourceRecord { getRRName   :: DomainName
                                     , getRRType   :: RRType
                                     , getRRClass  :: RRClass
                                     , getTTL      :: Word32
                                     , getRRData   :: ByteString
                                     }
                      deriving (Eq, Show, Read)

defaultMessage :: Message
defaultMessage = Message { getId                = 0
                         , isResponse           = False
                         , getOpcode            = query
                         , isAuthoritative      = False
                         , isTruncated          = False
                         , isRecursionDesired   = False
                         , isRecursionAvailable = False
                         , getZ                 = 0
                         , getResponseCode      = noError
                         , getQuestions         = []
                         , getAnswers           = []
                         , getAuthorities       = []
                         , getAdditional        = [] }

newtype RRType = RRType { fromRRType :: Word16 } deriving (Eq, Show, Read)
a        = RRType 1   -- a host address
ns       = RRType 2   -- an authoritative name server
md       = RRType 3   -- a mail destination (Obsolete - use MX)
mf       = RRType 4   -- a mail forwarder (Obsolete - use MX)
cname    = RRType 5   -- the canonical name for an alias
soa      = RRType 6   -- marks the start of a zone of authority
mb       = RRType 7   -- a mailbox domain name (EXPERIMENTAL)
mg       = RRType 8   -- a mail group member (EXPERIMENTAL)
mr       = RRType 9   -- a mail rename domain name (EXPERIMENTAL)
nullRR   = RRType 10  -- a null RR  -- (EXPERIMENTAL)
wks      = RRType 11  -- a well known service description
ptr      = RRType 12  -- a domain name pointer
hinfo    = RRType 13  -- host information
minfo    = RRType 14  -- mailbox or mail list information
mx       = RRType 15  -- mail exchange
txt      = RRType 16  -- text strings

newtype RRClass = RRClass { fromRRClass :: Word16 } deriving (Eq, Show, Read)
internet = RRClass 1  -- the Internet
csnet    = RRClass 2  -- the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
chaos    = RRClass 3  -- the CHAOS class
hesiod   = RRClass 4  -- Hesiod [Dyer 87]

newtype Opcode = Opcode { fromOpcode :: Word8 } deriving (Eq, Show, Read)
query    = Opcode 0
iquery   = Opcode 1
status   = Opcode 2

newtype ResponseCode = ResponseCode { fromResponseCode :: Word8 }
                       deriving (Eq, Show, Read)
noError        = ResponseCode 0
formatError    = ResponseCode 1
serverFailure  = ResponseCode 2
nameError      = ResponseCode 3
notImplemented = ResponseCode 4
refused        = ResponseCode 5

instance Serialize Message where
    put msg = do
        putHeader msg
        mapM_ put (getQuestions   msg)
        mapM_ put (getAnswers     msg)
        mapM_ put (getAuthorities msg)
        mapM_ put (getAdditional  msg)

    get = do
        msgId <- getWord16be
        [ isResp
          , opcode
          , authoritative
          , truncated
          , recDesired
          , recAvaialable
          , z
          , respCode ] <- liftM (unpackFlags [1, 4, 1, 1, 1, 1, 3, 4]) getWord16be
        qdcount     <- liftM fromIntegral getWord16be
        ancount     <- liftM fromIntegral getWord16be
        nscount     <- liftM fromIntegral getWord16be
        arcount     <- liftM fromIntegral getWord16be
        questions   <- replicateM qdcount get
        answers     <- replicateM ancount get
        authorities <- replicateM nscount get
        additional  <- replicateM arcount get
        return Message { getId                = msgId
                       , isResponse           = toBool isResp
                       , getOpcode            = Opcode (fromIntegral opcode)
                       , isAuthoritative      = toBool authoritative
                       , isTruncated          = toBool truncated
                       , isRecursionDesired   = toBool recDesired
                       , isRecursionAvailable = toBool recAvaialable
                       , getZ                 = fromIntegral z
                       , getResponseCode      = ResponseCode (fromIntegral respCode)
                       , getQuestions         = questions
                       , getAnswers           = answers
                       , getAuthorities       = authorities
                       , getAdditional        = additional }


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

putHeader :: Putter Message
putHeader msg = do
    putWord16be (getId msg)
    putWord16be (packFlags [
                      (fromBool         (isResponse           msg),  1)
      , (fromIntegral (fromOpcode       (getOpcode            msg)), 4)
      ,               (fromBool         (isAuthoritative      msg),  1)
      ,               (fromBool         (isTruncated          msg),  1)
      ,               (fromBool         (isRecursionDesired   msg),  1)
      ,               (fromBool         (isRecursionAvailable msg),  1)
      , (fromIntegral (                 getZ                  msg),  3)
      , (fromIntegral (fromResponseCode (getResponseCode      msg)), 4) ])
    putWord16be (fromIntegral (length (getQuestions   msg)))
    putWord16be (fromIntegral (length (getAnswers     msg)))
    putWord16be (fromIntegral (length (getAuthorities msg)))
    putWord16be (fromIntegral (length (getAdditional  msg)))

-- The first value in each tuple is the value of the flag, the second
-- value is the number of bits used to represent that value.
packFlags :: (Bits a) => [(a, Int)] -> a
packFlags = foldl' packFlag 0
    where packFlag packed (v, size) = (packed `shiftL` size) + v

unpackFlags :: (Bits a, Bounded a) => [Int] -> a -> [a]
unpackFlags sizes input = fst (foldr unpack ([], input) sizes)
    where unpack size (vs, packed) = let mask  = complement (maxBound `shiftL` size)
                                         value = packed .&. mask
                                         rest  = packed `shiftR` size
                                     in (value : vs, rest)


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

instance Serialize Question where
    put q = do
        put         (getQName  q)
        putWord16be (fromRRType  (getQType  q))
        putWord16be (fromRRClass (getQClass q))

    get = do
        name <- get
        t    <- liftM RRType  getWord16be
        c    <- liftM RRClass getWord16be
        return Question { getQName  = name
                        , getQType  = t
                        , getQClass = c }

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

instance Serialize ResourceRecord where
    put rr = do
        put           (getRRName  rr)
        putWord16be   (fromRRType  (getRRType  rr))
        putWord16be   (fromRRClass (getRRClass rr))
        putWord32be   (getTTL   rr)
        putWord16be   (fromIntegral (B.length (getRRData rr)))
        putByteString (getRRData rr)

    get = do
        name  <- get
        t     <- liftM RRType  getWord16be
        c     <- liftM RRClass getWord16be
        ttl   <- getWord32be
        len   <- getWord16be
        rdata <- getBytes (fromIntegral len)
        return ResourceRecord { getRRName  = name
                              , getRRType  = t
                              , getRRClass = c
                              , getTTL     = fromIntegral ttl
                              , getRRData  = rdata }

-- name limits:
-- * labels are 63 octects or fewer
-- * names are 255 octets or fewer, including dots, including final dot
instance Serialize DomainName where
    put (DomainName labels) = do
        mapM_ putLabel labels
        putWord8 0
      where
        putLabel l = do
            let bytes = fromString l
            putWord8 (fromIntegral (B.length bytes))
            putByteString bytes

    get = do
        labels <- getLabels
        return $ DomainName labels
      where
        getLabels = do
          len <- liftM fromIntegral getWord8
          if len == 0
          then return []
          else do
              bytes <- getBytes len
              let label = toString bytes
              rest <- getLabels
              return (label : rest)
