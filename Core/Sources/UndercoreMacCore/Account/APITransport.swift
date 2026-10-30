import Foundation

final class RejectRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

/// Owns HTTP delivery and origin boundaries; it knows nothing about accounts or offline data.
struct APITransport {
    let baseURL: URL
    private let session: URLSession

    init(baseURL: URL, session: URLSession?) throws {
        guard baseURL.scheme == "https", baseURL.host != nil,
              baseURL.user == nil, baseURL.password == nil,
              baseURL.path.isEmpty || baseURL.path == "/",
              baseURL.query == nil, baseURL.fragment == nil else { throw ClientError.invalidAddress }
        self.baseURL = baseURL
        self.session = session ?? Self.makeSession()
    }

    func url(for path: String) throws -> URL {
        guard path.hasPrefix("/"), !path.hasPrefix("//"), !path.contains("\\"),
              let url = URL(string: path, relativeTo: baseURL)?.absoluteURL,
              isSameOrigin(url) else { throw ClientError.invalidAddress }
        return url
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, rawResponse) = try await session.data(for: request)
        guard let response = rawResponse as? HTTPURLResponse,
              let url = response.url, isSameOrigin(url) else { throw ClientError.invalidResponse }
        return (data, response)
    }

    private func isSameOrigin(_ url: URL) -> Bool {
        url.scheme == baseURL.scheme && url.host == baseURL.host && url.port == baseURL.port
    }

    private static func makeSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = APILimits.requestTimeout
        configuration.timeoutIntervalForResource = APILimits.resourceTimeout
        configuration.waitsForConnectivity = false
        return URLSession(configuration: configuration, delegate: RejectRedirects(), delegateQueue: nil)
    }
}
