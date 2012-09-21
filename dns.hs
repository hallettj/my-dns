module Net.DNS () where

import Data.ByteString (ByteString)
--import Data.ByteString.Parser (getWord16be, Parser)
import Data.Int (Int32)
import Data.Serialize (decode, encode)
import Data.Serialize.Put (put, putWord16be)
import Data.Word (Word16)

newtype RRType = RRType String

data Message = Message { getHeader      :: Header
                       , getQuestions   :: [Question]
                       , getAnswers     :: [ResourceRecord]
                       , getAuthorities :: [ResourceRecord]
                       , getAdditional  :: [ResourceRecord]
                       }

data Header = Header { getId                :: Word16
                     , isResponse           :: Boolean
                     , getOpcode            :: Opcode  -- 4 bits
                     , isAuthoritative      :: Boolean
                     , isTruncated          :: Boolean
                     , isRecursionDesired   :: Boolean
                     , isRecursionAvailable :: Boolean
                     , getZ                 :: undefined  -- 3 bits, reserved for future use
                     , getResponseCode      :: ResponseCode  -- 4 bits
                     , getQDCount           :: Word16
                     , getANCount           :: Word16
                     , getNSCount           :: Word16
                     , getARCount           :: Word16
                     }

data Question = Question { getName  :: DomainName
                         , getType  :: Type   -- 16 bits
                         , getClass :: Class  -- 16 bits
                         }

data ResourceRecord = ResourceRecord { getName     :: DomainName
                                     , getType     :: Type   -- 16 bits
                                     , getClass    :: Class  -- 16 bits
                                     , getTTL      :: Int32
                                     , getRDLength :: Word16
                                     , getRData    :: ByteString
                                     }

-- TODO: create newtype for Word16, create values instead of
-- constructors
data Type = A     -- 1 a host address
          | NS    -- 2 an authoritative name server
          | MD    -- 3 a mail destination (Obsolete - use MX)
          | MF    -- 4 a mail forwarder (Obsolete - use MX)
          | CNAME -- 5 the canonical name for an alias
          | SOA   -- 6 marks the start of a zone of authority
          | MB    -- 7 a mailbox domain name (EXPERIMENTAL)
          | MG    -- 8 a mail group member (EXPERIMENTAL)
          | MR    -- 9 a mail rename domain name (EXPERIMENTAL)
          | NULL  -- 10 a null RR  -- (EXPERIMENTAL)
          | WKS   -- 11 a well known service description
          | PTR   -- 12 a domain name pointer
          | HINFO -- 13 host information
          | MINFO -- 14 mailbox or mail list information
          | MX    -- 15 mail exchange
          | TXT   -- 16 text strings
          deriving (Eq, Show)

data Class = IN -- 1 the Internet
           | CS -- 2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
           | CH -- 3 the CHAOS class
           | HS -- 4 Hesiod [Dyer 87]
           deriving (Eq, Show)

data Opcode = QUERY   -- 0
            | IQUERY  -- 1
            | STATUS  -- 2
            deriving (Eq, Show)

data ResponseCode = NoError        -- 0
                  | FormatError    -- 1
                  | ServerFailure  -- 2
                  | NameError      -- 3
                  | NotImplemented -- 4
                  | Refused        -- 5

putMessage msg = do
    putHeader msg
    mapM_ putRR (getQuestions msg)
    mapM_ putRR (getAnswers msg)
    mapM_ putRR (getAuthorities msg)
    mapM_ putRR (getAdditional msg)

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

putHeader msg = do
    putWord16be (getId msg)

    -- flags
    --put (isResponse msg)
    --putOpcode -- TODO
    --put (isAuthoritative msg)
    --put (isTruncated msg)
    --put (isRecursionDesired msg)
    --put (isRecursionAvailable msg)
    --skip 3  -- TODO
    --putRcode -- TODO

    let header = getHeader msg
    put (flags1 header)
    put (flags2 header)

    putWord16be (length (getQuestions   msg))
    putWord16be (length (getAnswers     msg))
    putWord16be (length (getAuthorities msg))
    putWord16be (length (getAdditional  msg))

flags1 :: Header -> Word8
flags1 header = let opcode = getOpcode header
                    shifted = opcode `shiftl` 3
                    isResp = if (isResponse header) 1 else 0
                    isAuth = if (isAuthoritative header) 1 else 0
                    recDes = if (isRecursionDesired header) 1 else 0
                in shifted + (isResp * 128) + (isAuth * 2) + recDes

flags2 :: Header -> Word8
flags2 header = let recAv = if (isRecursionAvailable) 1 else 0
                in (recAv * 128) + (getRcode header)

putRR rr = do
    put (getName rr)
    -- TODO


parseMessage = do
    id <- getWord16be
    isResponse <- getBoolean
               

parseMessage :: ByteString -> Either String Message
parseMessage msg = Message { getHeader = header
                           , getQuestions = questions
                           , getAnswers = answers
                           , getAuthorities = authorities
                           , getAdditional = additional
                           }
    where (header,      afterH)  = parseHeader msg
          (questions,   afterQD) = parseQuestions (getQDCount header) afterH
          (answers,     afterAN) = parseRRs (getANCount header) afterQD
          (authorities, afterNS) = parseRRs (getNSCount header) afterAN
          (additional,  _)       = parseRRs (getARCount header) afterNS

parseHeader :: ByteString -> (Either String Header, ByteString)
parseHeader msg = do
    (id, rest) <- decode msg
    (id, rest) <- parseWord msg

parseWord :: ByteString -> (Either String Word16, ByteString)
parseWord msg = getWord16be
