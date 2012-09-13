import Control.Monad (forever)
import Network.Socket (addrAddress
                     , addrFamily
                     , addrFlags
                     , AddrInfoFlag( AI_PASSIVE )
                     , bindSocket
                     , defaultHints
                     , defaultProtocol
                     , getAddrInfo
                     , recvFrom
                     , socket
                     , SocketType( Datagram )
                     , withSocketsDo)

port = "4444"

main = withSocketsDo $ do
    addrinfos <- getAddrInfo
                 (Just (defaultHints { addrFlags = [AI_PASSIVE] }))
                 Nothing (Just port)
    let serveraddr = head addrinfos
    sock <- socket (addrFamily serveraddr) Datagram defaultProtocol
    bindSocket sock (addrAddress serveraddr)

    putStrLn "waiting..."
    forever $ do
        (msg, len, from) <- recvFrom sock 1024
        putStrLn ("[received "++ (show len) ++" bytes from "++ (show from) ++"]")
        putStrLn msg
