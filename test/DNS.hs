module DNSTest (main) where

import Control.Monad (liftM)
import Data.List (intercalate)
import Data.Serialize (decode, encode)
import Data.Word (Word32)
import System.Random (Random)
import Test.QuickCheck
import Net.DNS

propSurvivesSerialization :: Message -> Bool
propSurvivesSerialization m = check $ decode (encode m)
    where check = either (const False) (== m)

propStableName :: DomainName -> Bool
propStableName n = check $ decode (encode n)
    where check = either (const False) (== n)

main = quickCheckWith stdArgs propSurvivesSerialization

-- name limits:
-- * labels are 63 octects or fewer
-- * names are 255 octets or fewer, including dots
-- * UDP messages are 512 octets or fewer
instance Arbitrary DomainName where
    arbitrary = do
        labels <- listOf arbitraryLabel `suchThat` ((<= 255) . sum . map length)
        return $ domainName (intercalate "." labels)
      where arbitraryLabel = arbitrary `suchThat` ((<= 64) . length)

instance Arbitrary Message where
    arbitrary = do
        msgId         <- arbitrary
        isResp        <- arbitrary
        opcode        <- arbitrary
        authoritative <- arbitrary
        truncated     <- arbitrary
        recDesired    <- arbitrary
        recAvailable  <- arbitrary
        z             <- bits 3
        respCode      <- arbitrary
        questions     <- arbitrary
        answers       <- arbitrary
        authorities   <- arbitrary
        additional    <- arbitrary
        return defaultMessage { getId                = msgId
                              , isResponse           = isResp
                              , getOpcode            = opcode
                              , isAuthoritative      = authoritative
                              , isTruncated          = truncated
                              , isRecursionDesired   = recDesired
                              , isRecursionAvailable = recAvailable
                              , getZ                 = z
                              , getResponseCode      = respCode
                              , getQuestions         = questions
                              , getAnswers           = answers
                              , getAuthorities       = authorities
                              , getAdditional        = additional }

instance Arbitrary Opcode where
    arbitrary = liftM Opcode (bits 4)

instance Arbitrary ResponseCode where
    arbitrary = liftM ResponseCode (bits 4)

instance Arbitrary Question where
    arbitrary = do
        name   <- arbitrary
        qType  <- arbitrary
        qClass <- arbitrary
        return Question { getQName  = name
                        , getQType  = qType
                        , getQClass = qClass }

instance Arbitrary ResourceRecord where
    arbitrary = do
        name    <- arbitrary
        rrType  <- arbitrary
        rrClass <- arbitrary
        ttl     <- arbitrary
        let d   =  arbitrary :: Gen Word32
        rrData  <- liftM encode d
        return ResourceRecord { getRRName  = name
                              , getRRType  = rrType
                              , getRRClass = rrClass
                              , getTTL     = ttl
                              , getRRData  = rrData }

instance Arbitrary RRType where
    arbitrary = liftM RRType arbitrary

instance Arbitrary RRClass where
    arbitrary = liftM RRClass arbitrary

bits :: (Integral a, Integral b, Random b) => a -> Gen b
bits n = choose (0, 2^n - 1)
