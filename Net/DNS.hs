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

import Control.Monad (liftM, replicateM, when)
import Control.Monad.State.Strict (evalStateT, StateT)
import qualified Control.Monad.State.Strict as State
import Control.Monad.Trans (lift)
import Data.ByteString (ByteString)
import qualified Data.ByteString      as B
import qualified Data.ByteString.UTF8 as UTF8
import Data.Bits ((.&.), Bits, complement, shiftL, shiftR)
import Data.List (foldl', intercalate, null)
import Data.List.Split (splitOn)
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Serialize (decode, get, put, Serialize)
import Data.Serialize.Get (Get, getBytes, getWord8, getWord16be, getWord32be, lookAhead, skip)
import Data.Serialize.Put (Put, PutM, putByteString, putWord8, putWord16be, putWord32be, Putter)
import Data.Word (Word8, Word16, Word32)
import Foreign.Marshal.Utils (fromBool, toBool)
import Prelude hiding (lookup, null)

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
                                     , getRRData   :: ByteString }
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


-- state Monad to track label offsets for decompressing domain names

type GetS a = StateT (Maybe ReadState) Get a

data ReadState = ReadState { getBytesRead :: Int
                           , labelOffsets :: Map Int [String] }

insert :: Integral a => a -> [String] -> Maybe ReadState -> Maybe ReadState
insert k v = fmap insert'
    where insert' (ReadState b o) = ReadState b (Map.insert k' v o)
          k' = fromIntegral k

lookup :: Integral a => a -> Maybe ReadState -> Maybe [String]
lookup k = (>>= Map.lookup (fromIntegral k) . labelOffsets)

readBytes :: Integral a => a -> Maybe ReadState -> Maybe ReadState
readBytes n = fmap increment'
    where increment' (ReadState b o) = ReadState (b + n') o
          n' = fromIntegral n

bytesRead :: Maybe ReadState -> Int
bytesRead = maybe 0 getBytesRead

emptyState :: Maybe ReadState
emptyState = Just (ReadState 0 Map.empty)

noState :: Maybe ReadState
noState = Nothing


-- state Monad to track label offsets for compressing domain names

type PutS = StateT (Maybe ReadState) PutM ()

wroteBytes   = readBytes
bytesWritten = bytesRead


-- serialization and deserialization code

getMessage :: GetS Message
getMessage = do
    msgId <- getWord16
    [ isResp
      , opcode
      , authoritative
      , truncated
      , recDesired
      , recAvaialable
      , z
      , respCode ] <- liftM (unpackFlags [1, 4, 1, 1, 1, 1, 3, 4]) getWord16
    qdcount        <- liftM fromIntegral getWord16
    ancount        <- liftM fromIntegral getWord16
    nscount        <- liftM fromIntegral getWord16
    arcount        <- liftM fromIntegral getWord16
    State.modify $ readBytes 12
    questions      <- replicateM qdcount getQuestion
    answers        <- replicateM ancount getResourceRecord
    authorities    <- replicateM nscount getResourceRecord
    additional     <- replicateM arcount getResourceRecord
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

putMessage :: Message -> PutS
putMessage msg = do
    lift $ putHeader msg
    State.modify $ wroteBytes 12
    mapM_ putQuestion       (getQuestions   msg)
    mapM_ putResourceRecord (getAnswers     msg)
    mapM_ putResourceRecord (getAuthorities msg)
    mapM_ putResourceRecord (getAdditional  msg)

instance Serialize Message where
    put msg = evalStateT (putMessage msg) emptyState
    get     = evalStateT getMessage       emptyState


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

getQuestion :: GetS Question
getQuestion = do
    name <- getDomainName
    t    <- liftM RRType  getWord16
    c    <- liftM RRClass getWord16
    State.modify $ readBytes 4  -- 4 bytes for type and class
    return Question { getQName  = name
                    , getQType  = t
                    , getQClass = c }

putQuestion :: Question -> PutS
putQuestion q = do
    putDomainName (getQName  q)
    putWord16     (fromRRType  (getQType  q))
    putWord16     (fromRRClass (getQClass q))
    State.modify $ wroteBytes 4

instance Serialize Question where
    put q = evalStateT (putQuestion q) noState
    get   = evalStateT getQuestion     noState

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

getResourceRecord :: GetS ResourceRecord
getResourceRecord = do
    name  <- getDomainName
    t     <- liftM RRType  getWord16
    c     <- liftM RRClass getWord16
    ttl   <- getWord32
    len   <- getWord16
    rdata <- lift $ getBytes (fromIntegral len)
    State.modify $ readBytes (10 + len)
    return ResourceRecord { getRRName  = name
                          , getRRType  = t
                          , getRRClass = c
                          , getTTL     = fromIntegral ttl
                          , getRRData  = rdata }

putResourceRecord :: ResourceRecord -> PutS
putResourceRecord rr = do
    putDomainName (getRRName  rr)
    putWord16     (fromRRType  (getRRType  rr))
    putWord16     (fromRRClass (getRRClass rr))
    putWord32     (getTTL   rr)
    let rrData     = getRRData rr
    let dataLength = B.length rrData
    putWord16     (fromIntegral dataLength)
    lift $ putByteString rrData
    State.modify $ wroteBytes (10 + fromIntegral dataLength)

instance Serialize ResourceRecord where
    put rr = evalStateT (putResourceRecord rr) noState
    get    = evalStateT getResourceRecord      noState

-- TODO: name limits:
-- * labels are 63 octects or fewer
-- * names are 255 octets or fewer, including dots, including final dot
getDomainName :: GetS DomainName
getDomainName = do
    labels <- getLabels
    return $ DomainName labels
  where
    getLabels = do
        len <- lift $ liftM fromIntegral $ lookAhead getWord8
        case len of
            _ | len == 0   -> lift (skip 1) >> return []
              | len <  64  -> do
                  offset <- State.gets bytesRead
                  lift $ skip 1
                  bytes <- lift $ getBytes len
                  let label = UTF8.toString bytes
                  State.modify $ readBytes (1 + len)
                  ls <- getLabels
                  State.modify $ insert offset (label : ls)
                  return (label : ls)
              | len >= 192 -> do
                  referencedOffset <- liftM (\n -> n - 49152) getWord16
                  State.modify $ readBytes 2
                  ref <- State.gets $ lookup (referencedOffset - 49152)
                  case ref of
                      Just ls -> return ls
                      Nothing -> fail ("Invalid label offset: "++ show referencedOffset)
              | otherwise  -> fail ("Unknown label length octet value: "++ show len)

putDomainName :: DomainName -> PutS
putDomainName (DomainName labels) = putLabels labels
  where
    putLabels labels@(l:ls) = do
        offset <- State.gets bytesWritten
        State.modify $ insert offset labels
        let bytes = UTF8.fromString l
        let len   = fromIntegral (B.length bytes)
        when (len > 63) $ fail ("Domain name label exceeds 63 octets: "++ l)
        lift $ putWord8 len
        lift $ putByteString bytes
        State.modify $ wroteBytes (1 + len)
        putLabels ls
    putLabels [] = do
        lift $ putWord8 0
        State.modify $ wroteBytes 1

instance Serialize DomainName where
    put name = evalStateT (putDomainName name) noState
    get      = evalStateT getDomainName        noState

getWord16 :: GetS Word16
getWord16 = lift getWord16be

getWord32 :: GetS Word32
getWord32 = lift getWord32be

putWord16 :: Word16 -> PutS
putWord16 = lift . putWord16be

putWord32 :: Word32 -> PutS
putWord32 = lift . putWord32be
