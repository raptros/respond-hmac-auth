module Web.Respond.Auth.HMAC where

import Control.Applicative ((<$>))
import Control.Monad.IO.Class
import Control.Monad.Trans.Cont
import Crypto.Hash

import Network.Wai
import qualified Web.Respond as R
import qualified Network.Wai.Auth.HMAC as Auth

-- | a class for things that have a secret key in them
class HasSecretKey a where
    getSecretKey :: a -> Auth.SecretKey

instance HasSecretKey Auth.SecretKey where
    getSecretKey = id

-- | gets the api key from the request in the current context
getApiKey :: R.MonadRespond m => Auth.ApiKeySpec -> m (Maybe Auth.ApiKey)
getApiKey spec = Auth.getApiKey spec <$> R.getRequest 

-- | performs the 'Auth.authenticate' operation on the request in the
-- current context.
authenticate :: (R.MonadRespond m, HasSecretKey a, HashAlgorithm alg) 
             => Auth.RequestConfig alg 
             -> a
             -> m (Either Auth.AuthFailure Request)
authenticate conf principal = R.getRequest >>= \req -> liftIO (Auth.authenticate conf req (getSecretKey principal))

-- | runs the inner route with the loaded principal if the current request
-- passes the authentication check. it performs the steps
--
-- - get the api key from the request
-- - call the principal loader
-- - perform 'authenticate' on the request
--
--  and if all steps succeed, runs the inner route with the new request
--  value in the context.
--
--  if any of the steps fail, withHmacAuth calls 'R.handleAuthFailed' with
--  the reportable error. (for the first step, this is the ReportableError
--  constructed from 'Auth.MissingApiKey'.
withHmacAuth :: (R.ReportableError e, R.ReportableError f, R.MonadRespond m, HashAlgorithm alg, HasSecretKey a) 
             => Auth.RequestConfig alg -- ^ configuration for authentication
             -> (Auth.AuthFailure -> e) -- ^ how to represent an auth failure as a reportable error
             -> (Auth.ApiKey -> m (Either f a)) -- ^ action that loads the principal for the api key
             -> (a -> m ResponseReceived) -- ^ inner route
             -> m ResponseReceived
withHmacAuth conf authFailureRep getPrincipal innerRoute = evalCont $ do
    apiKey    <- contMaybe (respFailure (Auth.MissingApiKey keySpec)) $ getApiKey keySpec
    principal <- contEither R.handleAuthFailed $ getPrincipal apiKey 
    authReq   <- contEither respFailure $ authenticate conf principal
    return $ R.withRequest authReq $ innerRoute principal
    where
    keySpec = Auth.keySpec conf
    respFailure = R.handleAuthFailed . authFailureRep

-- | if the monadic Maybe is Nothing, ends with the first value, otherwise
-- continues with the Just value.
contMaybe :: Monad m => m b -> m (Maybe a) -> Cont (m b) a
contMaybe onFail act = cont $ \c -> act >>= maybe onFail c

-- | if the monadic value is Left, ends using the function, otherwise
-- continues with the Right value
contEither :: Monad m => (e -> m b) -> m (Either e c) -> Cont (m b) c
contEither onFail act = cont $ \c -> act >>= either onFail c
