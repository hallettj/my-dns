module DNSTest (main) where

import qualified Codec.Binary.UTF8.String as UTF8
import Control.Monad (liftM, replicateM)
import qualified Data.ByteString as BS
import Data.List (intercalate)
import Data.Binary (decode, encode)
import Data.Word (Word32)
import System.Random (Random)
import Test.QuickCheck
import Net.DNS

propSurvivesSerialization :: Message -> Bool
propSurvivesSerialization m = check $ decode (encode m)
    where check :: Either String Message -> Bool
          check = either (const False) (== m)

propStableName :: DomainName -> Bool
propStableName n = check $ decode (encode n)
    where check :: Either String DomainName -> Bool
          check = either (const False) (== n)

main = quickCheckWith stdArgs propSurvivesSerialization

-- name limits:
-- * labels are 63 octects or fewer
-- * names are 255 octets or fewer, including dots
-- * UDP messages are 512 octets or fewer
instance Arbitrary DomainName where
    arbitrary = do
        num    <- (arbitrary :: Gen Word32) `suchThat` (> 0)
        labels <- buildLabels num []
        return $ domainName (intercalate "." labels)
      where buildLabels n ls = do
                label <- buildLabel
                if totalLen (label : ls) > 255
                then return ls
                else buildLabels (n - 1) (label : ls)
            buildLabel = do
                randomLabel `suchThat` ((<= 63) . len)
            randomLabel = do
                l <- choose (1, 63)
                replicateM l arbitrary
            totalLen ls = sum (map len ls) + length ls
            len = length . UTF8.encode

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
        rrData  <- liftM BS.pack arbitrary
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
