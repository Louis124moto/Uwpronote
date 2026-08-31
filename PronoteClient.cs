using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Windows.Data.Json;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;

namespace PronoteLumia
{
    public class HomeworkModel
    {
        public string Subject { get; set; }
        public string Description { get; set; }
        public DateTime DueDate { get; set; }

        public string FormattedDate
        {
            get { return DueDate.ToString("dd/MM"); }
        }
    }

    public class ScheduleModel
    {
        public string Subject { get; set; }
        public string Room { get; set; }
        public string TimeSlot { get; set; }
    }

    public class PronoteClient
    {
        private readonly HttpClient _http;

        private string _rootUrl;
        private string _htmlPage;

        private string _sessionId;
        private int _espaceId;

        private byte[] _aesKey;
        private byte[] _aesIv;

        private byte[] _temporaryIv;

        private int _requestOrder = 1;

        private bool _encryptRequests;
        private bool _compressRequests;

        private JsonObject _userResource;

        public PronoteClient()
        {
            _http = new HttpClient();

            _http.DefaultRequestHeaders.TryAddWithoutValidation(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            );

            // PRONOTE doit être utilisé en HTTPS.
            _aesKey = Md5Bytes(new byte[0]);
            _aesIv = new byte[16];
        }

        // =========================================================
        // AUTHENTIFICATION
        // =========================================================

        public async Task<bool> AuthenticateAsync(
            string pronoteUrl,
            string username,
            string password)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(pronoteUrl))
                    return false;

                if (string.IsNullOrWhiteSpace(username))
                    return false;

                if (string.IsNullOrWhiteSpace(password))
                    return false;

                ParseUrl(pronoteUrl);

                if (!_rootUrl.StartsWith("https://",
                    StringComparison.OrdinalIgnoreCase))
                {
                    throw new Exception(
                        "Le serveur PRONOTE doit utiliser HTTPS."
                    );
                }

                // -------------------------------------------------
                // 1. Récupération de eleve.html
                // -------------------------------------------------

                string html = await _http.GetStringAsync(
                    _rootUrl + "/" + _htmlPage
                );

                ParseStartParameters(html);

                // -------------------------------------------------
                // 2. IV temporaire
                // -------------------------------------------------

                _temporaryIv = new byte[16];

                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(_temporaryIv);
                }

                // PRONOTE HTTPS accepte directement l'IV en Base64.
                string uuid =
                    Convert.ToBase64String(_temporaryIv);

                // -------------------------------------------------
                // 3. FonctionParametres
                // -------------------------------------------------

                JsonObject initData = new JsonObject();

                initData.Add(
                    "Uuid",
                    JsonValue.CreateStringValue(uuid)
                );

                initData.Add(
                    "identifiantNav",
                    JsonValue.CreateStringValue("")
                );

                JsonObject initResponse =
                    await PostFunctionAsync(
                        "FonctionParametres",
                        initData,
                        Md5Bytes(_temporaryIv)
                    );

                if (initResponse == null)
                    return false;

                // Le serveur peut demander le chiffrement/compression.
                if (initResponse.ContainsKey("CrA"))
                    _encryptRequests =
                        initResponse.GetNamedBoolean("CrA");

                if (initResponse.ContainsKey("CoA"))
                    _compressRequests =
                        initResponse.GetNamedBoolean("CoA");

                // Les paramètres sont généralement dans dataSec.
                JsonObject parameters =
                    GetDataSec(initResponse);

                // -------------------------------------------------
                // 4. Identification
                // -------------------------------------------------

                JsonObject identification =
                    new JsonObject();

                identification.Add(
                    "genreConnexion",
                    JsonValue.CreateNumberValue(0)
                );

                identification.Add(
                    "genreEspace",
                    JsonValue.CreateNumberValue(_espaceId)
                );

                identification.Add(
                    "identifiant",
                    JsonValue.CreateStringValue(username)
                );

                identification.Add(
                    "pourENT",
                    JsonValue.CreateBooleanValue(false)
                );

                identification.Add(
                    "enConnexionAuto",
                    JsonValue.CreateBooleanValue(false)
                );

                identification.Add(
                    "demandeConnexionAuto",
                    JsonValue.CreateBooleanValue(false)
                );

                identification.Add(
                    "demandeConnexionAppliMobile",
                    JsonValue.CreateBooleanValue(false)
                );

                identification.Add(
                    "demandeConnexionAppliMobileJeton",
                    JsonValue.CreateBooleanValue(false)
                );

                identification.Add(
                    "enConnexionAppliMobile",
                    JsonValue.CreateBooleanValue(false)
                );

                identification.Add(
                    "uuidAppliMobile",
                    JsonValue.CreateStringValue("")
                );

                identification.Add(
                    "loginTokenSAV",
                    JsonValue.CreateStringValue("")
                );

                JsonObject identificationResponse =
                    await PostFunctionAsync(
                        "Identification",
                        identification
                    );

                if (identificationResponse == null)
                    return false;

                JsonObject identificationData =
                    GetDataSec(identificationResponse);

                string challenge =
                    GetString(
                        identificationData,
                        "challenge"
                    );

                string alea =
                    GetString(
                        identificationData,
                        "alea"
                    );

                if (string.IsNullOrEmpty(challenge))
                    return false;

                int modeCompMdp =
                    GetInt(
                        identificationData,
                        "modeCompMdp"
                    );

                int modeCompLog =
                    GetInt(
                        identificationData,
                        "modeCompLog"
                    );

                string login = username;
                string pwd = password;

                if (modeCompLog == 1)
                    login = login.ToLowerInvariant();

                if (modeCompMdp == 1)
                    pwd = pwd.ToLowerInvariant();

                // -------------------------------------------------
                // 5. Calcul du challenge
                // -------------------------------------------------

                string mtp =
                    Sha256Hex(
                        alea + pwd
                    ).ToUpperInvariant();

                byte[] authKey =
                    Md5Bytes(
                        Encoding.UTF8.GetBytes(
                            login + mtp
                        )
                    );

                string solvedChallenge =
                    SolveChallenge(
                        challenge,
                        authKey
                    );

                // -------------------------------------------------
                // 6. Authentification
                // -------------------------------------------------

                JsonObject authentication =
                    new JsonObject();

                authentication.Add(
                    "connexion",
                    JsonValue.CreateNumberValue(0)
                );

                authentication.Add(
                    "challenge",
                    JsonValue.CreateStringValue(
                        solvedChallenge
                    )
                );

                authentication.Add(
                    "espace",
                    JsonValue.CreateNumberValue(_espaceId)
                );

                JsonObject authResponse =
                    await PostFunctionAsync(
                        "Authentification",
                        authentication
                    );

                if (authResponse == null)
                    return false;

                JsonObject authData =
                    GetDataSec(authResponse);

                // -------------------------------------------------
                // 7. Nouvelle clé AES PRONOTE
                // -------------------------------------------------

                string cle =
                    GetString(
                        authData,
                        "cle"
                    );

                if (!string.IsNullOrEmpty(cle))
                {
                    byte[] encryptedKey =
                        HexToBytes(cle);

                    byte[] decodedKey =
                        AesDecrypt(
                            encryptedKey,
                            authKey,
                            _aesIv
                        );

                    string numbers =
                        Encoding.UTF8.GetString(
                            decodedKey
                        );

                    byte[] realKey =
                        ParseByteList(numbers);

                    _aesKey =
                        Md5Bytes(realKey);
                }

                // -------------------------------------------------
                // 8. Paramètres utilisateur
                // -------------------------------------------------

                JsonObject userResponse =
                    await PostFunctionAsync(
                        "ParametresUtilisateur",
                        new JsonObject()
                    );

                if (userResponse != null)
                {
                    JsonObject userData =
                        GetDataSec(userResponse);

                    if (userData.ContainsKey("ressource"))
                    {
                        _userResource =
                            userData.GetNamedObject(
                                "ressource"
                            );
                    }
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        // =========================================================
        // DEVOIRS
        // =========================================================

        public async Task<List<HomeworkModel>> GetHomeworkAsync()
        {
            var result = new List<HomeworkModel>();

            try
            {
                JsonObject data = new JsonObject();

                JsonObject response =
                    await PostFunctionAsync(
                        "PageCahierDeTextes",
                        data
                    );

                if (response == null)
                    return result;

                JsonObject root =
                    GetDataSec(response);

                JsonArray array = null;

                if (root.ContainsKey("ListeDevoirs"))
                {
                    array =
                        root.GetNamedArray(
                            "ListeDevoirs"
                        );
                }

                if (array == null)
                    return result;

                foreach (IJsonValue value in array)
                {
                    JsonObject item =
                        value.GetObject();

                    string subject =
                        GetStringAny(
                            item,
                            "Matiere",
                            "matiere",
                            "place"
                        );

                    string description =
                        GetStringAny(
                            item,
                            "Descriptif",
                            "descriptif",
                            "description"
                        );

                    DateTime date =
                        DateTime.Now;

                    string dateString =
                        GetStringAny(
                            item,
                            "Date",
                            "date",
                            "dateDuJour"
                        );

                    DateTime.TryParse(
                        dateString,
                        out date
                    );

                    result.Add(
                        new HomeworkModel
                        {
                            Subject =
                                string.IsNullOrEmpty(subject)
                                    ? "Matière inconnue"
                                    : subject,

                            Description =
                                description ?? "",

                            DueDate =
                                date == DateTime.MinValue
                                    ? DateTime.Now
                                    : date
                        }
                    );
                }
            }
            catch
            {
            }

            return result
                .OrderBy(x => x.DueDate)
                .ToList();
        }

        // =========================================================
        // EMPLOI DU TEMPS
        // =========================================================

        public async Task<List<ScheduleModel>> GetScheduleAsync()
        {
            var result =
                new List<ScheduleModel>();

            try
            {
                if (_userResource == null)
                    return result;

                JsonObject data =
                    new JsonObject();

                data.Add(
                    "ressource",
                    _userResource
                );

                data.Add(
                    "Ressource",
                    _userResource
                );

                int week =
                    GetCurrentSchoolWeek();

                data.Add(
                    "numeroSemaine",
                    JsonValue.CreateNumberValue(week)
                );

                data.Add(
                    "NumeroSemaine",
                    JsonValue.CreateNumberValue(week)
                );

                data.Add(
                    "avecAbsencesEleve",
                    JsonValue.CreateBooleanValue(false)
                );

                data.Add(
                    "avecConseilDeClasse",
                    JsonValue.CreateBooleanValue(true)
                );

                data.Add(
                    "estEDTPermanence",
                    JsonValue.CreateBooleanValue(false)
                );

                data.Add(
                    "avecAbsencesRessource",
                    JsonValue.CreateBooleanValue(true)
                );

                data.Add(
                    "avecDisponibilites",
                    JsonValue.CreateBooleanValue(true)
                );

                data.Add(
                    "avecInfosPrefsGrille",
                    JsonValue.CreateBooleanValue(true)
                );

                JsonObject response =
                    await PostFunctionAsync(
                        "PageEmploiDuTemps",
                        data
                    );

                if (response == null)
                    return result;

                JsonObject root =
                    GetDataSec(response);

                JsonArray courses = null;

                if (root.ContainsKey("ListeCours"))
                {
                    courses =
                        root.GetNamedArray(
                            "ListeCours"
                        );
                }

                if (courses == null)
                    return result;

                foreach (IJsonValue value in courses)
                {
                    JsonObject item =
                        value.GetObject();

                    result.Add(
                        new ScheduleModel
                        {
                            Subject =
                                GetStringAny(
                                    item,
                                    "place",
                                    "matiere",
                                    "Matiere"
                                ) ?? "Cours",

                            Room =
                                GetStringAny(
                                    item,
                                    "salle",
                                    "Salle"
                                ) ?? "Salle N/A",

                            TimeSlot =
                                GetStringAny(
                                    item,
                                    "horaire",
                                    "Horaire"
                                ) ?? ""
                        }
                    );
                }
            }
            catch
            {
            }

            return result;
        }

        // =========================================================
        // REQUÊTES PRONOTE
        // =========================================================

        private async Task<JsonObject> PostFunctionAsync(
            string functionName,
            JsonObject data,
            byte[] temporaryKey = null)
        {
            int order = _requestOrder;

            string orderEncrypted =
                EncryptOrder(
                    order,
                    temporaryKey ?? _aesKey,
                    temporaryKey != null
                        ? Md5Bytes(_temporaryIv)
                        : _aesIv
                );

            string dataSec =
                data.Stringify();

            byte[] dataBytes =
                Encoding.UTF8.GetBytes(
                    dataSec
                );

            if (_encryptRequests)
            {
                dataSec =
                    BytesToHex(
                        AesEncrypt(
                            dataBytes,
                            temporaryKey ?? _aesKey,
                            temporaryKey != null
                                ? Md5Bytes(_temporaryIv)
                                : _aesIv
                        )
                    ).ToUpperInvariant();
            }

            JsonObject request =
                new JsonObject();

            request.Add(
                "session",
                JsonValue.CreateNumberValue(
                    int.Parse(_sessionId)
                )
            );

            request.Add(
                "no",
                JsonValue.CreateStringValue(
                    orderEncrypted
                )
            );

            request.Add(
                "id",
                JsonValue.CreateStringValue(
                    functionName
                )
            );

            request.Add(
                "dataSec",
                JsonValue.CreateStringValue(
                    dataSec
                )
            );

            string url =
                _rootUrl +
                "/appelfonction/" +
                _espaceId +
                "/" +
                _sessionId +
                "/" +
                orderEncrypted;

            var content =
                new StringContent(
                    request.Stringify(),
                    Encoding.UTF8,
                    "application/json"
                );

            HttpResponseMessage response =
                await _http.PostAsync(
                    url,
                    content
                );

            if (!response.IsSuccessStatusCode)
                return null;

            string responseText =
                await response.Content
                    .ReadAsStringAsync();

            JsonObject responseJson;

            if (!JsonObject.TryParse(
                    responseText,
                    out responseJson))
            {
                return null;
            }

            // Chaque requête et chaque réponse consomme
            // un numéro d'ordre.
            _requestOrder += 2;

            if (!responseJson.ContainsKey("dataSec"))
                return responseJson;

            JsonValue sec =
                responseJson.GetNamedValue(
                    "dataSec"
                ) as JsonValue;

            if (sec == null)
                return responseJson;

            string encrypted =
                sec.GetString();

            if (!_encryptRequests)
            {
                JsonObject plain;

                if (JsonObject.TryParse(
                    encrypted,
                    out plain))
                {
                    responseJson.SetNamedValue(
                        "dataSec",
                        plain
                    );
                }

                return responseJson;
            }

            try
            {
                byte[] encryptedBytes =
                    HexToBytes(encrypted);

                byte[] plainBytes =
                    AesDecrypt(
                        encryptedBytes,
                        temporaryKey ?? _aesKey,
                        temporaryKey != null
                            ? Md5Bytes(_temporaryIv)
                            : _aesIv
                    );

                string plain =
                    Encoding.UTF8.GetString(
                        plainBytes
                    );

                JsonObject obj;

                if (JsonObject.TryParse(
                    plain,
                    out obj))
                {
                    responseJson.SetNamedValue(
                        "dataSec",
                        obj
                    );
                }
            }
            catch
            {
                return null;
            }

            return responseJson;
        }

        // =========================================================
        // PARSING HTML
        // =========================================================

        private void ParseUrl(string url)
        {
            url = url.Trim();

            if (url.EndsWith("/"))
                url =
                    url.Substring(
                        0,
                        url.Length - 1
                    );

            int index =
                url.LastIndexOf('/');

            if (index <= 8)
                throw new Exception(
                    "URL PRONOTE invalide."
                );

            _rootUrl =
                url.Substring(
                    0,
                    index
                );

            _htmlPage =
                url.Substring(
                    index + 1
                );

            if (string.IsNullOrEmpty(_htmlPage))
                _htmlPage = "eleve.html";
        }

        private void ParseStartParameters(
            string html)
        {
            Match match =
                Regex.Match(
                    html,
                    @"Start\s*\(\s*\{([^}]*)\}"
                );

            if (!match.Success)
            {
                throw new Exception(
                    "Impossible de trouver les paramètres PRONOTE."
                );
            }

            string parameters =
                match.Groups[1].Value;

            Dictionary<string, string> values =
                new Dictionary<string, string>();

            string[] parts =
                parameters.Split(',');

            foreach (string part in parts)
            {
                string[] pair =
                    part.Split(
                        new[] { ':' },
                        2
                    );

                if (pair.Length != 2)
                    continue;

                string key =
                    pair[0]
                        .Trim()
                        .Trim('\'', '"');

                string value =
                    pair[1]
                        .Trim()
                        .Trim('\'', '"');

                values[key] = value;
            }

            if (!values.ContainsKey("h"))
                throw new Exception(
                    "Session PRONOTE introuvable."
                );

            _sessionId =
                values["h"];

            if (values.ContainsKey("a"))
            {
                int.TryParse(
                    values["a"],
                    out _espaceId
                );
            }

            // CrA = chiffrement demandé par le serveur.
            if (values.ContainsKey("sCrA"))
            {
                bool.TryParse(
                    values["sCrA"],
                    out _encryptRequests
                );
            }

            // CoA = compression.
            // Cette implémentation ne traite pas encore
            // la compression brute zlib de PRONOTE.
            if (values.ContainsKey("sCoA"))
            {
                bool compression;

                bool.TryParse(
                    values["sCoA"],
                    out compression
                );

                if (compression)
                {
                    throw new Exception(
                        "Ce serveur PRONOTE demande la compression."
                    );
                }
            }
        }

        // =========================================================
        // CHALLENGE
        // =========================================================

        private string SolveChallenge(
            string challengeHex,
            byte[] key)
        {
            byte[] encrypted =
                HexToBytes(challengeHex);

            byte[] decrypted =
                AesDecrypt(
                    encrypted,
                    key,
                    _aesIv
                );

            string text =
                Encoding.UTF8.GetString(
                    decrypted
                );

            // PRONOTE conserve un caractère sur deux.
            StringBuilder result =
                new StringBuilder();

            for (int i = 0; i < text.Length; i += 2)
            {
                result.Append(text[i]);
            }

            byte[] solved =
                AesEncrypt(
                    Encoding.UTF8.GetBytes(
                        result.ToString()
                    ),
                    key,
                    _aesIv
                );

            return BytesToHex(
                solved
            ).ToUpperInvariant();
        }

        // =========================================================
        // AES
        // =========================================================

        private byte[] AesEncrypt(
            byte[] data,
            byte[] key,
            byte[] iv)
        {
            var provider =
                SymmetricKeyAlgorithmProvider.OpenAlgorithm(
                    SymmetricAlgorithmNames.AesCbcPkcs7
                );

            var keyBuffer =
                CryptographicBuffer.CreateFromByteArray(
                    key
                );

            var ivBuffer =
                CryptographicBuffer.CreateFromByteArray(
                    iv
                );

            var dataBuffer =
                CryptographicBuffer.CreateFromByteArray(
                    data
                );

            var cryptKey =
                provider.CreateSymmetricKey(
                    keyBuffer
                );

            var encrypted =
                CryptographicEngine.Encrypt(
                    cryptKey,
                    dataBuffer,
                    ivBuffer
                );

            byte[] result;

            CryptographicBuffer.CopyToByteArray(
                encrypted,
                out result
            );

            return result;
        }

        private byte[] AesDecrypt(
            byte[] data,
            byte[] key,
            byte[] iv)
        {
            var provider =
                SymmetricKeyAlgorithmProvider.OpenAlgorithm(
                    SymmetricAlgorithmNames.AesCbcPkcs7
                );

            var keyBuffer =
                CryptographicBuffer.CreateFromByteArray(
                    key
                );

            var ivBuffer =
                CryptographicBuffer.CreateFromByteArray(
                    iv
                );

            var dataBuffer =
                CryptographicBuffer.CreateFromByteArray(
                    data
                );

            var cryptKey =
                provider.CreateSymmetricKey(
                    keyBuffer
                );

            var decrypted =
                CryptographicEngine.Decrypt(
                    cryptKey,
                    dataBuffer,
                    ivBuffer
                );

            byte[] result;

            CryptographicBuffer.CopyToByteArray(
                decrypted,
                out result
            );

            return result;
        }

        // =========================================================
        // HASH
        // =========================================================

        private byte[] Md5Bytes(byte[] data)
        {
            HashAlgorithmProvider provider =
                HashAlgorithmProvider.OpenAlgorithm(
                    HashAlgorithmNames.Md5
                );

            IBuffer buffer =
                CryptographicBuffer.CreateFromByteArray(
                    data
                );

            IBuffer hash =
                provider.HashData(buffer);

            byte[] result;

            CryptographicBuffer.CopyToByteArray(
                hash,
                out result
            );

            return result;
        }

        private string Sha256Hex(string text)
        {
            HashAlgorithmProvider provider =
                HashAlgorithmProvider.OpenAlgorithm(
                    HashAlgorithmNames.Sha256
                );

            IBuffer input =
                CryptographicBuffer.ConvertStringToBinary(
                    text,
                    BinaryStringEncoding.Utf8
                );

            IBuffer hash =
                provider.HashData(input);

            return CryptographicBuffer
                .EncodeToHexString(hash);
        }

        // =========================================================
        // OUTILS
        // =========================================================

        private string EncryptOrder(
            int number,
            byte[] key,
            byte[] iv)
        {
            byte[] encrypted =
                AesEncrypt(
                    Encoding.UTF8.GetBytes(
                        number.ToString()
                    ),
                    key,
                    iv
                );

            return BytesToHex(
                encrypted
            ).ToLowerInvariant();
        }

        private JsonObject GetDataSec(
            JsonObject response)
        {
            if (!response.ContainsKey("dataSec"))
                return response;

            JsonObject data =
                response.GetNamedObject(
                    "dataSec"
                );

            if (data.ContainsKey("donnees"))
                return data.GetNamedObject(
                    "donnees"
                );

            return data;
        }

        private string GetString(
            JsonObject obj,
            string name)
        {
            if (!obj.ContainsKey(name))
                return "";

            try
            {
                return obj.GetNamedString(
                    name
                );
            }
            catch
            {
                return "";
            }
        }

        private int GetInt(
            JsonObject obj,
            string name)
        {
            if (!obj.ContainsKey(name))
                return 0;

            try
            {
                return (int)obj.GetNamedNumber(
                    name
                );
            }
            catch
            {
                return 0;
            }
        }

        private string GetStringAny(
            JsonObject obj,
            params string[] names)
        {
            foreach (string name in names)
            {
                string value =
                    GetString(obj, name);

                if (!string.IsNullOrEmpty(value))
                    return value;
            }

            return "";
        }

        private byte[] ParseByteList(
            string value)
        {
            string[] parts =
                value.Split(',');

            List<byte> bytes =
                new List<byte>();

            foreach (string part in parts)
            {
                int number;

                if (int.TryParse(
                    part.Trim(),
                    out number))
                {
                    if (number >= 0 &&
                        number <= 255)
                    {
                        bytes.Add(
                            (byte)number
                        );
                    }
                }
            }

            return bytes.ToArray();
        }

        private string BytesToHex(
            byte[] bytes)
        {
            StringBuilder sb =
                new StringBuilder(
                    bytes.Length * 2
                );

            foreach (byte b in bytes)
            {
                sb.Append(
                    b.ToString("x2")
                );
            }

            return sb.ToString();
        }

        private byte[] HexToBytes(
            string hex)
        {
            if (hex.Length % 2 != 0)
                throw new Exception(
                    "Chaîne hexadécimale invalide."
                );

            byte[] bytes =
                new byte[hex.Length / 2];

            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] =
                    Convert.ToByte(
                        hex.Substring(i * 2, 2),
                        16
                    );
            }

            return bytes;
        }

        private int GetCurrentSchoolWeek()
        {
            // Valeur de secours.
            // PRONOTE peut fournir une date de début
            // d'année dans FonctionParametres.
            DateTime start =
                new DateTime(
                    DateTime.Now.Year,
                    9,
                    1
                );

            TimeSpan difference =
                DateTime.Now - start;

            if (difference.TotalDays < 0)
                start =
                    start.AddYears(-1);

            return
                1 +
                (int)(
                    (DateTime.Now - start)
                    .TotalDays / 7
                );
        }
    }
}
