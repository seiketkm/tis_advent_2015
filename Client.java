import java.net.URL;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.Socket;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext; 
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509KeyManager;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.KeyStore;
import java.io.FileInputStream;

public class Client {
	public static void main(String[] args) throws Exception {
		executeGet("First",  "client1"); //成功
		executeGet("Second", "client1"); //失敗
		executeGet("First",  "client2"); //失敗
		executeGet("Second", "client2"); //成功
	}                       

	/**                     
	 * @param o GETリクエストで送信するパラメータ
	 * @param alias                         
	 *            KeyStoreから証明書を選択するときに使うalias
	 * @throws Exception
	 */             
	private static void executeGet(String o, String alias) throws Exception {
		System.out.println("=== HTTP GET Start ===");

		URL url = new URL("https://localhost:8000/get?o=" + o);
		// 動的にクライアント証明書を選択しない（お任せ挙動）
		// SSLSocketFactory sslsocketfactory = (SSLSocketFactory)SSLSocketFactory.getDefault();
		// 動的にクライアント証明書を選択する為の
		SSLSocketFactory sslsocketfactory = getSSLSocketFactory(alias);

		HttpsURLConnection connection = null;
		connection = (HttpsURLConnection) url.openConnection();
		connection.setSSLSocketFactory(sslsocketfactory);
		connection.setRequestMethod("GET");

		// サーバからの応答が200のときだけレスポンスを表示する
		if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
			try {
				InputStreamReader isr = new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8);
				BufferedReader reader = new BufferedReader(isr);
				String line;
				while ((line = reader.readLine()) != null) {
					System.out.println(line);
				}
			} finally {
				if (connection != null) {
					connection.disconnect();
				}
			}
		}
		System.out.println("=== HTTP GET End ===");
	}

	private static SSLSocketFactory getSSLSocketFactory(String alias) throws Exception {
		// キーマネージャを取得
		KeyManagerFactory factory = KeyManagerFactory.getInstance("NewSunX509", "SunJSSE");
		
		// キーストアの情報を取得
		String keyStore = System.getProperty("javax.net.ssl.keyStore");
		String keyStorePass = System.getProperty("javax.net.ssl.keyStorePassword");
		FileInputStream fis=new FileInputStream(keyStore);
		KeyStore ks=KeyStore.getInstance("jks");
		ks.load(fis, keyStorePass.toCharArray());
		fis.close();

		factory.init(ks, keyStorePass.toCharArray());
		KeyManager[] kms = factory.getKeyManagers();
		// キーマネージャをラップする。
		if (alias != null) {
			for (int i=0; i<kms.length; i++) {
				if (kms[i] instanceof X509KeyManager)                       
					kms[i]=new AliasForcingKeyManager((X509KeyManager)kms[i], alias);
			}                   
		}               
		//キーマネージャを変更してSSLSocketFactoryを作成 
		SSLContext context = SSLContext.getInstance("SSL");
		context.init(kms, null, null);
		SSLSocketFactory ssf = context.getSocketFactory();
		return ssf;
	}

	/*      
	 * X509KeyManagerのラッパークラス
	 * chooseClientAliasを変更し、他は元の挙動。 
	 */
	public static class AliasForcingKeyManager implements X509KeyManager {
		private X509KeyManager km; 
		private String alias;
		public AliasForcingKeyManager(X509KeyManager km, String alias) {
			this.km = km;
			this.alias = alias;
		}

		@Override
		public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
			for (String keyType : keyTypes) {
				String[] validAliases = km.getClientAliases(keyType, issuers);
				if (validAliases == null)
					continue;
				for (String validAlias : validAliases) {
					// 参考サイトではequalsでやっていたがprefixが付いていたのでcontainsで
					// 証明書を選択する。
					//System.out.println(validAlias);
					//System.out.println(alias);
					if (validAlias.contains(alias)){
					    //System.out.println(alias);
						return validAlias;
					}
				}
			}
			return null;
		}
		@Override
		public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
			return km.chooseServerAlias(keyType, issuers, socket);
		}
		@Override
		public java.security.cert.X509Certificate[] getCertificateChain(String alias) {
			return km.getCertificateChain(alias);
		}
		@Override
		public String[] getClientAliases(String keyType, Principal[] issuers) {
			return km.getClientAliases(keyType, issuers);
		}
		@Override
		public PrivateKey getPrivateKey(String alias) {
			return km.getPrivateKey(alias);
		}
		@Override
		public String[] getServerAliases(String keyType, Principal[] issuers) {
			return km.getServerAliases(keyType, issuers);
		}
	}
}
