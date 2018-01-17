module Network.RandomString where

import           Data.String (IsString(..))
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base58 as Base58
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Base16 as Base16
import           Control.Monad.IO.Class
import           System.Entropy

data StringOpts = StringOpts { alphabet :: Alphabet, nrBytes :: Int }
data Alphabet = Base58 | Base16 | Base64

randomString :: (MonadIO m, IsString s) => StringOpts -> m s
randomString opts =
    let getE n = maybe (getEntropy n) pure =<< getHardwareEntropy n
        conv = fromString . B8.unpack
        enc = case alphabet opts of
                Base58 -> Base58.encodeBase58 Base58.bitcoinAlphabet
                Base16 -> Base16.encode
                Base64 -> Base64.encode
    in (conv . enc) <$> liftIO (getE (nrBytes opts))

