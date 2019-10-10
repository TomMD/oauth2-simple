{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE TypeOperators     #-}
{-# LANGUAGE OverloadedStrings #-}
import Network.OAuth2 as OA
import Servant.HTML.Lucid
import Lucid
import Data.Proxy
import Servant.Server
import Servant
import System.Environment
import Network.Wai.Handler.Warp
import Data.Text as T

data Landing = Landing Text

data Authorized = AuthorizedFailed
                | AuthorizedSuccess Text String

type API =    Get '[HTML] Landing
         :<|> "authorized" :> QueryParam "code" Text :> QueryParam "state" Text :> Get '[HTML] Authorized

instance ToHtml Landing where
    toHtml (Landing addr) =
        do title_ "Auth to GitHub (test)"
           a_ [href_ addr] "Click here to oauth"
    toHtmlRaw = toHtml

instance ToHtml Authorized where
    toHtml AuthorizedFailed =
      do title_ "Failed"
         body_ $ h1_ "FAILED"
    toHtml (AuthorizedSuccess s t) =
      do title_ "Authorized"
         body_ $ do p_ (toHtml s)
                    p_ (toHtml t)
    toHtmlRaw = toHtml

gh :: Text -> Text -> Text -> OAuth2
gh cid csecret callback =
     OAuth2 { oauthClientId = cid
            , oauthClientSecret = csecret
            , oauthOAuthorizeEndpoint = "https://github.com/login/oauth/authorize"
            , oauthAccessTokenEndpoint = "https://github.com/login/oauth/access_token"
            , oauthCallback = callback -- e.x. http://127.0.0.1/authorized
            , oauthScopes = []
            }

doLanding :: OAuth2 -> OAuthState -> Handler Landing
doLanding oa authSt = do
    url <- getAuthorize authSt oa mempty
    pure $ Landing url

doAuthorized :: OAuth2 -> OAuthState -> Maybe Text -> Maybe Text -> Handler Authorized
doAuthorized oa authState mc ms =
  do mtoken <- getAuthorized oa authState mc ms
     case mtoken of
        Just (token,_) -> pure $ AuthorizedSuccess token (show ms)
        Nothing    -> pure $ AuthorizedFailed

server :: OAuth2 -> OAuthState -> Server API
server oa auth =  doLanding oa auth
          :<|> doAuthorized oa auth

api :: Proxy API
api = Proxy

main :: IO ()
main =
  do [clientId, clientSecret, callback] <- fmap T.pack <$> getArgs
     let oa = gh clientId clientSecret callback
     oauthState <- OA.newOAuthStateWith oauthStateNonce
     run 8181 (serve api (server oa oauthState))
