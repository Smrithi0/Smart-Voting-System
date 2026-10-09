import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.*;

public class Server {

    static Map<String, String> userSessions = new HashMap<>();
    static Map<String, String> adminSessions = new HashMap<>();

    // FORGOT PASSWORD OTP
    static Map<String, String> otpStore = new HashMap<>();
    static Random random = new Random();

    public static void main(String[] args) throws Exception {

        new File("data").mkdirs();

        HttpServer server = HttpServer.create(
                new InetSocketAddress(9090),
                0
        );

        // ================= LOGIN =================

        server.createContext("/login", ex -> {

            try {

                if (!ex.getRequestMethod().equalsIgnoreCase("POST")) {

                    sendFile(ex, "login.html");
                    return;
                }

                String body = new String(
                        ex.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8
                );

                Map<String, String> d = parse(body);

                String name = d.getOrDefault("name", "").trim();
                String login = d.getOrDefault("login", "").trim();
                String password = d.getOrDefault("password", "").trim();

                // ADMIN LOGIN

                if (name.equals("admin")
                        && login.equals("admin@gmail.com")
                        && password.equals("admin@123")) {

                    String sid = UUID.randomUUID().toString();

                    adminSessions.put(sid, "admin");

                    ex.getResponseHeaders().add(
                            "Set-Cookie",
                            "ADMIN=" + sid + "; path=/"
                    );

                    redirect(ex, "/adminDashboard.html");
                    return;
                }

                // USER LOGIN

                boolean userExists = false;

                String hashed = hash(password);

                for (String line : read("data/users.txt")) {

                    String[] p = line.split(",");

                    if (p.length >= 4
                            && p[0].equals(name)
                            && (p[1].equals(login)
                            || p[2].equals(login))) {

                        userExists = true;

                        if (p[3].equals(hashed)) {

                            String sid = UUID.randomUUID().toString();

                            userSessions.put(sid, p[2]);

                            ex.getResponseHeaders().add(
                                    "Set-Cookie",
                                    "USER=" + sid + "; path=/"
                            );

                            redirect(ex, "/userDashboard.html");
                            return;

                        } else {

                            sendText(ex, "WRONG_PASSWORD");
                            return;
                        }
                    }
                }

                if (userExists) {

                    sendText(ex, "WRONG_PASSWORD");

                } else {

                    sendText(ex, "USER_NOT_FOUND");
                }

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        // ================= REGISTER =================

        server.createContext("/register", ex -> {

            try {

                if (!ex.getRequestMethod().equalsIgnoreCase("POST")) {

                    sendFile(ex, "register.html");
                    return;
                }

                String body = new String(
                        ex.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8
                );

                Map<String, String> d = parse(body);

                String name = d.getOrDefault("name", "").trim();
                String phone = d.getOrDefault("phone", "").trim();
                String email = d.getOrDefault("email", "").trim();
                String password = d.getOrDefault("password", "").trim();

                if (name.isEmpty()
                        || phone.isEmpty()
                        || email.isEmpty()
                        || password.isEmpty()) {

                    sendText(ex, "ALL_FIELDS_REQUIRED");
                    return;
                }

                if (!validPassword(password)) {

                    sendText(
                            ex,
                            "Password must contain uppercase, lowercase, number, special character and minimum 10 characters"
                    );

                    return;
                }

                for (String line : read("data/users.txt")) {

                    String[] p = line.split(",");

                    if (p.length >= 3 && p[2].equals(email)) {

                        sendText(ex, "EMAIL_ALREADY_EXISTS");
                        return;
                    }
                }

                write(
                        "data/users.txt",
                        name + "," +
                                phone + "," +
                                email + "," +
                                hash(password)
                );

                redirect(ex, "/login.html");

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        // ================= USER PROFILE =================

        server.createContext("/userProfile", ex -> {

            try {

                String email = "";

                List<String> cookies =
                        ex.getRequestHeaders().get("Cookie");

                if (cookies != null) {

                    for (String cookie : cookies) {

                        for (String c : cookie.split(";")) {

                            c = c.trim();

                            if (c.startsWith("USER=")) {

                                String sid = c.substring(5);

                                email =
                                        userSessions.getOrDefault(sid, "");
                            }
                        }
                    }
                }

                List<String> users = read("data/users.txt");

                for (String line : users) {

                    String[] p = line.split(",");

                    if (p.length >= 4 && p[2].equals(email)) {

                        String json = "{"
                                + "\"name\":\"" + p[0] + "\","
                                + "\"phone\":\"" + p[1] + "\","
                                + "\"email\":\"" + p[2] + "\""
                                + "}";

                        sendJSON(ex, json);
                        return;
                    }
                }

                sendJSON(ex, "{}");

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        // ================= UPDATE PROFILE =================

        server.createContext("/updateProfile", ex -> {

            try {

                String body = new String(
                        ex.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8
                );

                Map<String, String> d = parse(body);

                String newName = d.getOrDefault("name", "").trim();
                String newPhone = d.getOrDefault("phone", "").trim();

                String email = "";

                List<String> cookies =
                        ex.getRequestHeaders().get("Cookie");

                if (cookies != null) {

                    for (String cookie : cookies) {

                        for (String c : cookie.split(";")) {

                            c = c.trim();

                            if (c.startsWith("USER=")) {

                                String sid = c.substring(5);

                                email =
                                        userSessions.getOrDefault(sid, "");
                            }
                        }
                    }
                }

                List<String> users = read("data/users.txt");
                List<String> updated = new ArrayList<>();

                for (String line : users) {

                    String[] p = line.split(",");

                    if (p.length >= 4 && p[2].equals(email)) {

                        updated.add(
                                newName + "," +
                                        newPhone + "," +
                                        p[2] + "," +
                                        p[3]
                        );

                    } else {

                        updated.add(line);
                    }
                }

                overwrite("data/users.txt", updated);

                sendText(ex, "PROFILE_UPDATED");

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        // ================= CHANGE PASSWORD =================

        server.createContext("/changePassword", ex -> {

            try {

                String body = new String(
                        ex.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8
                );

                Map<String, String> d = parse(body);

                String oldPassword =
                        d.getOrDefault("oldPassword", "").trim();

                String newPassword =
                        d.getOrDefault("newPassword", "").trim();

                String email = "";

                List<String> cookies =
                        ex.getRequestHeaders().get("Cookie");

                if (cookies != null) {

                    for (String cookie : cookies) {

                        for (String c : cookie.split(";")) {

                            c = c.trim();

                            if (c.startsWith("USER=")) {

                                String sid = c.substring(5);

                                email =
                                        userSessions.getOrDefault(sid, "");
                            }
                        }
                    }
                }

                List<String> users = read("data/users.txt");
                List<String> updated = new ArrayList<>();

                boolean changed = false;

                for (String line : users) {

                    String[] p = line.split(",");

                    if (p.length >= 4 && p[2].equals(email)) {

                        if (!p[3].equals(hash(oldPassword))) {

                            sendText(ex, "WRONG_OLD_PASSWORD");
                            return;
                        }

                        updated.add(
                                p[0] + "," +
                                        p[1] + "," +
                                        p[2] + "," +
                                        hash(newPassword)
                        );

                        changed = true;

                    } else {

                        updated.add(line);
                    }
                }

                if (changed) {

                    overwrite("data/users.txt", updated);

                    sendText(ex, "PASSWORD_CHANGED");

                } else {

                    sendText(ex, "USER_NOT_FOUND");
                }

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        // ================= SEND OTP =================

        server.createContext("/sendOTP", ex -> {

            try {

                String body = new String(
                        ex.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8
                );

                Map<String, String> d = parse(body);

                String email = d.getOrDefault("email", "").trim();

                if (email.isEmpty()) {

                    sendText(ex, "EMAIL_REQUIRED");
                    return;
                }

                boolean found = false;

                for (String line : read("data/users.txt")) {

                    String[] p = line.split(",");

                    if (p.length >= 3 && p[2].equals(email)) {

                        found = true;
                        break;
                    }
                }

                if (!found) {

                    sendText(ex, "USER_NOT_FOUND");
                    return;
                }

                String otp = String.valueOf(
                        100000 + random.nextInt(900000)
                );

                otpStore.put(email, otp);

                sendText(ex, "DUMMY OTP: " + otp);

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        // ================= RESET PASSWORD =================

        server.createContext("/resetPassword", ex -> {

            try {

                String body = new String(
                        ex.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8
                );

                Map<String, String> d = parse(body);

                String email = d.getOrDefault("email", "").trim();
                String otp = d.getOrDefault("otp", "").trim();

                String newPassword =
                        d.getOrDefault("newPassword", "").trim();

                if (email.isEmpty()
                        || otp.isEmpty()
                        || newPassword.isEmpty()) {

                    sendText(ex, "ALL_FIELDS_REQUIRED");
                    return;
                }

                String savedOtp = otpStore.get(email);

                if (savedOtp == null || !savedOtp.equals(otp)) {

                    sendText(ex, "INVALID_OTP");
                    return;
                }

                if (!validPassword(newPassword)) {

                    sendText(
                            ex,
                            "Password must contain uppercase, lowercase, number, special character and minimum 10 characters"
                    );

                    return;
                }

                List<String> users = read("data/users.txt");
                List<String> updated = new ArrayList<>();

                boolean changed = false;

                for (String line : users) {

                    String[] p = line.split(",");

                    if (p.length >= 4 && p[2].equals(email)) {

                        updated.add(
                                p[0] + "," +
                                        p[1] + "," +
                                        p[2] + "," +
                                        hash(newPassword)
                        );

                        changed = true;

                    } else {

                        updated.add(line);
                    }
                }

                if (changed) {

                    overwrite("data/users.txt", updated);

                    otpStore.remove(email);

                    sendText(ex, "PASSWORD_RESET_SUCCESS");

                } else {

                    sendText(ex, "USER_NOT_FOUND");
                }

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        // ================= LOGOUT =================

        server.createContext("/logout", ex -> {

            ex.getResponseHeaders().add(
                    "Set-Cookie",
                    "USER=; path=/; Max-Age=0"
            );

            ex.getResponseHeaders().add(
                    "Set-Cookie",
                    "ADMIN=; path=/; Max-Age=0"
            );

            redirect(ex, "/login.html");
        });

        // ================= ADD EVENT =================

        server.createContext("/addEvent", ex -> {

            try {

                String body = new String(
                        ex.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8
                );

                Map<String, String> d = parse(body);

                String event = d.getOrDefault("event", "").trim();

                if (event.isEmpty()) {

                    sendText(ex, "EVENT_REQUIRED");
                    return;
                }

                String id =
                        String.valueOf(System.currentTimeMillis());

                write(
                        "data/events.txt",
                        id + "," + event + ",ACTIVE"
                );

                sendText(ex, "EVENT_ADDED");

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        // ================= END EVENT =================

        server.createContext("/endEvent", ex -> {

            try {

                String body = new String(
                        ex.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8
                );

                Map<String, String> d = parse(body);

                String id = d.getOrDefault("id", "");

                List<String> updated = new ArrayList<>();

                for (String line : read("data/events.txt")) {

                    String[] p = line.split(",");

                    if (p[0].equals(id)) {

                        p[2] = "ENDED";
                    }

                    updated.add(String.join(",", p));
                }

                overwrite("data/events.txt", updated);

                sendText(ex, "EVENT_ENDED");

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        // ================= LIST EVENTS =================

        server.createContext("/listEvents", ex -> {

            try {

                sendJSON(ex, getEventsJSON(false));

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        // ================= EVENT HISTORY =================

        server.createContext("/eventHistory", ex -> {

            try {

                sendJSON(ex, getEventsJSON(true));

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        // ================= ADD CANDIDATE =================

        server.createContext("/addCandidate", ex -> {

            try {

                String body = new String(
                        ex.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8
                );

                Map<String, String> d = parse(body);

                String eventId =
                        d.getOrDefault("eventId", "").trim();

                String name =
                        d.getOrDefault("name", "").trim();

                String party =
                        d.getOrDefault("party", "").trim();

                if (eventId.isEmpty()
                        || name.isEmpty()
                        || party.isEmpty()) {

                    sendText(ex, "ALL_FIELDS_REQUIRED");
                    return;
                }

                write(
                        "data/candidates.txt",
                        eventId + "," + name + "," + party
                );

                sendText(ex, "CANDIDATE_ADDED");

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        // ================= REMOVE CANDIDATE =================

        server.createContext("/removeCandidate", ex -> {

            try {

                String body = new String(
                        ex.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8
                );

                Map<String, String> d = parse(body);

                String eventId =
                        d.getOrDefault("eventId", "");

                String name =
                        d.getOrDefault("name", "");

                List<String> updated = new ArrayList<>();

                for (String line : read("data/candidates.txt")) {

                    String[] p = line.split(",");

                    if (!(p[0].equals(eventId)
                            && p[1].equals(name))) {

                        updated.add(line);
                    }
                }

                overwrite("data/candidates.txt", updated);

                sendText(ex, "CANDIDATE_REMOVED");

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        // ================= LIST CANDIDATES =================

        server.createContext("/listCandidates", ex -> {

            try {

                sendJSON(ex, getCandidatesJSON(false));

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        // ================= VOTE =================

        server.createContext("/vote", ex -> {

            try {

                String body = new String(
                        ex.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8
                );

                Map<String, String> d = parse(body);

                String email =
                        d.getOrDefault("email", "").trim();

                String eventId =
                        d.getOrDefault("eventId", "").trim();

                String candidate =
                        d.getOrDefault("candidate", "").trim();

                if (email.isEmpty()
                        || eventId.isEmpty()
                        || candidate.isEmpty()) {

                    sendText(ex, "ALL_FIELDS_REQUIRED");
                    return;
                }

                boolean active = false;

                for (String line : read("data/events.txt")) {

                    String[] p = line.split(",");

                    if (p.length >= 3
                            && p[0].equals(eventId)
                            && p[2].equals("ACTIVE")) {

                        active = true;
                    }
                }

                if (!active) {

                    sendText(ex, "EVENT_ENDED");
                    return;
                }

                for (String line : read("data/votes.txt")) {

                    String[] p = line.split(",");

                    if (p.length >= 3
                            && p[0].equals(email)
                            && p[1].equals(eventId)) {

                        write(
                                "data/fraud.txt",
                                email + "," +
                                        eventId + "," +
                                        candidate + "," +
                                        "DUPLICATE_ATTEMPT"
                        );

                        sendText(ex, "FRAUD_DETECTED");
                        return;
                    }
                }

                write(
                        "data/votes.txt",
                        email + "," +
                                eventId + "," +
                                candidate
                );

                sendText(ex, "VOTE_CASTED");

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        // ================= LIVE RESULTS =================

        server.createContext("/liveResults", ex -> {

            try {

                Map<String, Integer> resultMap =
                        new HashMap<>();

                for (String line : read("data/votes.txt")) {

                    String[] p = line.split(",");

                    if (p.length >= 3) {

                        String candidate = p[2];

                        resultMap.put(
                                candidate,
                                resultMap.getOrDefault(candidate, 0) + 1
                        );
                    }
                }

                StringBuilder json =
                        new StringBuilder("{");

                boolean first = true;

                for (String key : resultMap.keySet()) {

                    if (!first) {

                        json.append(",");
                    }

                    json.append("\"")
                            .append(key)
                            .append("\":")
                            .append(resultMap.get(key));

                    first = false;
                }

                json.append("}");

                sendJSON(ex, json.toString());

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        // ================= FRAUD LOGS =================

        server.createContext("/fraudLogs", ex -> {

            try {

                List<String> logs =
                        read("data/fraud.txt");

                StringBuilder html =
                        new StringBuilder();

                html.append("<html><body>");
                html.append("<h2>Fraud Logs</h2>");

                if (logs.isEmpty()) {

                    html.append("<p>No fraud detected</p>");
                }

                for (String log : logs) {

                    html.append("<p>")
                            .append(log)
                            .append("</p><hr>");
                }

                html.append("</body></html>");

                sendHTML(ex, html.toString());

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        // ================= STATIC FILES =================

        server.createContext("/", ex -> {

            try {

                String path =
                        ex.getRequestURI().getPath();

                if (path.equals("/")) {

                    path = "/login.html";
                }

                File file = new File("web" + path);

                if (!file.exists()) {

                    ex.sendResponseHeaders(404, -1);
                    return;
                }

                byte[] data =
                        Files.readAllBytes(file.toPath());

                if (path.endsWith(".html")) {

                    ex.getResponseHeaders().set(
                            "Content-Type",
                            "text/html; charset=UTF-8"
                    );

                } else if (path.endsWith(".css")) {

                    ex.getResponseHeaders().set(
                            "Content-Type",
                            "text/css"
                    );

                } else if (path.endsWith(".js")) {

                    ex.getResponseHeaders().set(
                            "Content-Type",
                            "application/javascript"
                    );
                }

                ex.sendResponseHeaders(200, data.length);

                OutputStream os = ex.getResponseBody();

                os.write(data);

                os.close();

            } catch (Exception e) {

                e.printStackTrace();
                safeError(ex);
            }
        });

        server.start();

        System.out.println(
                "Running at http://localhost:9090"
        );
    }

    // ================= EVENTS JSON =================

    static String getEventsJSON(boolean historyOnly)
            throws Exception {

        List<String> list = read("data/events.txt");

        StringBuilder json = new StringBuilder("[");

        boolean first = true;

        for (String line : list) {

            String[] p = line.split(",");

            if (p.length < 3) {

                continue;
            }

            if (historyOnly
                    && !p[2].equals("ENDED")) {

                continue;
            }

            if (!historyOnly
                    && !p[2].equals("ACTIVE")) {

                continue;
            }

            if (!first) {

                json.append(",");
            }

            json.append("{")
                    .append("\"id\":\"")
                    .append(p[0])
                    .append("\",")

                    .append("\"name\":\"")
                    .append(p[1])
                    .append("\",")

                    .append("\"status\":\"")
                    .append(p[2])
                    .append("\"")

                    .append("}");

            first = false;
        }

        json.append("]");

        return json.toString();
    }

    // ================= CANDIDATES JSON =================

    static String getCandidatesJSON(boolean historyOnly)
            throws Exception {

        List<String> candidates =
                read("data/candidates.txt");

        List<String> events =
                read("data/events.txt");

        Set<String> validEventIds =
                new HashSet<>();

        for (String event : events) {

            String[] e = event.split(",");

            if (e.length < 3) {

                continue;
            }

            if (historyOnly
                    && e[2].equals("ENDED")) {

                validEventIds.add(e[0]);
            }

            if (!historyOnly
                    && e[2].equals("ACTIVE")) {

                validEventIds.add(e[0]);
            }
        }

        StringBuilder json =
                new StringBuilder("[");

        boolean first = true;

        for (String line : candidates) {

            String[] p = line.split(",");

            if (p.length < 3) {

                continue;
            }

            if (!validEventIds.contains(p[0])) {

                continue;
            }

            if (!first) {

                json.append(",");
            }

            json.append("{")
                    .append("\"eventId\":\"")
                    .append(p[0])
                    .append("\",")

                    .append("\"name\":\"")
                    .append(p[1])
                    .append("\",")

                    .append("\"party\":\"")
                    .append(p[2])
                    .append("\"")

                    .append("}");

            first = false;
        }

        json.append("]");

        return json.toString();
    }

    // ================= PASSWORD VALIDATION =================

    static boolean validPassword(String pwd) {

        if (pwd == null) {

            return false;
        }

        return pwd.matches(
                "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@#$%^&+=!]).{10,}$"
        );
    }

    // ================= HASH =================

    static String hash(String input)
            throws Exception {

        MessageDigest md =
                MessageDigest.getInstance("SHA-256");

        byte[] bytes =
                md.digest(input.getBytes());

        StringBuilder sb =
                new StringBuilder();

        for (byte b : bytes) {

            sb.append(String.format("%02x", b));
        }

        return sb.toString();
    }

    // ================= REDIRECT =================

    static void redirect(HttpExchange ex, String url)
            throws IOException {

        ex.getResponseHeaders()
                .add("Location", url);

        ex.sendResponseHeaders(302, -1);
    }

    // ================= SEND FILE =================

    static void sendFile(HttpExchange ex, String file)
            throws IOException {

        byte[] data = Files.readAllBytes(
                Paths.get("web/" + file)
        );

        ex.sendResponseHeaders(200, data.length);

        ex.getResponseBody().write(data);

        ex.close();
    }

    // ================= SEND TEXT =================

    static void sendText(HttpExchange ex, String text)
            throws IOException {

        byte[] data = text.getBytes();

        ex.sendResponseHeaders(200, data.length);

        ex.getResponseBody().write(data);

        ex.close();
    }

    // ================= SEND JSON =================

    static void sendJSON(HttpExchange ex, String text)
            throws IOException {

        ex.getResponseHeaders().set(
                "Content-Type",
                "application/json"
        );

        sendText(ex, text);
    }

    // ================= SEND HTML =================

    static void sendHTML(HttpExchange ex, String html)
            throws IOException {

        byte[] data =
                html.getBytes(StandardCharsets.UTF_8);

        ex.getResponseHeaders().set(
                "Content-Type",
                "text/html"
        );

        ex.sendResponseHeaders(200, data.length);

        ex.getResponseBody().write(data);

        ex.close();
    }

    // ================= SAFE ERROR =================

    static void safeError(HttpExchange ex) {

        try {

            ex.sendResponseHeaders(500, -1);

        } catch (Exception ignored) {
        }
    }

    // ================= READ FILE =================

    static List<String> read(String file)
            throws IOException {

        File f = new File(file);

        if (!f.exists()) {

            return new ArrayList<>();
        }

        return Files.readAllLines(f.toPath());
    }

    // ================= WRITE FILE =================

    static void write(String file, String data)
            throws IOException {

        new File("data").mkdirs();

        try (FileWriter fw =
                     new FileWriter(file, true)) {

            fw.write(data + "\n");
        }
    }

    // ================= OVERWRITE FILE =================

    static void overwrite(
            String file,
            List<String> data
    ) throws IOException {

        try (FileWriter fw =
                     new FileWriter(file)) {

            for (String s : data) {

                fw.write(s + "\n");
            }
        }
    }

    // ================= PARSE =================

    static Map<String, String> parse(String body) {

        Map<String, String> map =
                new HashMap<>();

        if (body == null || body.isEmpty()) {

            return map;
        }

        for (String pair : body.split("&")) {

            String[] p = pair.split("=", 2);

            if (p.length == 2) {

                map.put(
                        URLDecoder.decode(
                                p[0],
                                StandardCharsets.UTF_8
                        ),

                        URLDecoder.decode(
                                p[1],
                                StandardCharsets.UTF_8
                        )
                );
            }
        }

        return map;
    }
}