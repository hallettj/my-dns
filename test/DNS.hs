module DNSTest (main) where

import Control.Monad (liftM)
import Data.Serialize (decode, encode)
import System.Random (Random)
import Test.QuickCheck
import Net.DNS

propSurvivesSerialization :: Message -> Bool
propSurvivesSerialization m = check $ decode (encode m)
    where check = either (const False) (== m)

main = quickCheckWith stdArgs propSurvivesSerialization

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
        return defaultMessage { getId                = msgId
                              , isResponse           = isResp
                              , getOpcode            = opcode
                              , isAuthoritative      = authoritative
                              , isTruncated          = truncated
                              , isRecursionDesired   = recDesired
                              , isRecursionAvailable = recAvailable
                              , getZ                 = z
                              , getResponseCode      = respCode }

instance Arbitrary Opcode where
    arbitrary = liftM Opcode (bits 4)

instance Arbitrary ResponseCode where
    arbitrary = liftM ResponseCode (bits 4)

bits :: (Integral a, Integral b, Random b) => a -> Gen b
bits n = choose (0, 2^n - 1)
