package com.psc65.passwordchecker;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Handles password strength checks for GET and POST requests.
 * The form submits using POST, while GET simply redirects the user
 * back to the main form page.
 */
@WebServlet("/password-checker")
public class PasswordServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Pattern UPPERCASE_PATTERN = Pattern.compile(".*[A-Z].*");
    private static final Pattern DIGIT_PATTERN = Pattern.compile(".*\\d.*");
    private static final Pattern SPECIAL_CHARACTER_PATTERN = Pattern.compile(".*[^a-zA-Z0-9].*");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.sendRedirect(request.getContextPath() + "/index.html");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        request.setCharacterEncoding("UTF-8");
        response.setContentType("text/html;charset=UTF-8");

        // Retrieve the password entered in the HTML form.
        String password = request.getParameter("password");
        if (password == null) {
            password = "";
        }

        boolean hasMinimumLength = password.length() >= 8;
        boolean hasUppercase = UPPERCASE_PATTERN.matcher(password).matches();
        boolean hasDigit = DIGIT_PATTERN.matcher(password).matches();
        boolean hasSpecialCharacter = SPECIAL_CHARACTER_PATTERN.matcher(password).matches();

        int passedRules = countPassedRules(
                hasMinimumLength,
                hasUppercase,
                hasDigit,
                hasSpecialCharacter
        );

        String strength = determineStrength(passedRules);
        String strengthClass = determineStrengthClass(strength);
        List<String> improvementTips = buildImprovementTips(
                hasMinimumLength,
                hasUppercase,
                hasDigit,
                hasSpecialCharacter
        );
        int progressPercentage = passedRules * 25;

        try (PrintWriter out = response.getWriter()) {
            out.println("<!DOCTYPE html>");
            out.println("<html lang=\"en\">");
            out.println("<head>");
            out.println("<meta charset=\"UTF-8\">");
            out.println("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
            out.println("<title>Password Strength Result</title>");
            out.println("<style>");
            out.println(":root {"
                    + "--bg:#f5efe4;"
                    + "--card:#fffdf8;"
                    + "--ink:#1f2933;"
                    + "--border:#d8c8a8;"
                    + "--pass:#15803d;"
                    + "--fail:#b91c1c;"
                    + "--weak:#dc2626;"
                    + "--medium:#ea580c;"
                    + "--strong:#15803d;"
                    + "}");
            out.println("* { box-sizing: border-box; }");
            out.println("body {"
                    + "margin:0;"
                    + "min-height:100vh;"
                    + "display:grid;"
                    + "place-items:center;"
                    + "padding:24px;"
                    + "font-family:\"Trebuchet MS\",\"Gill Sans\",sans-serif;"
                    + "color:var(--ink);"
                    + "background:linear-gradient(135deg,#f7f1e3,#eef6f5);"
                    + "}");
            out.println(".card {"
                    + "width:min(100%,620px);"
                    + "background:var(--card);"
                    + "border:1px solid var(--border);"
                    + "border-radius:22px;"
                    + "padding:32px 28px;"
                    + "box-shadow:0 18px 45px rgba(31,41,51,0.12);"
                    + "}");
            out.println("h1 { margin:0 0 12px; color:#134e4a; }");
            out.println("p { margin:0 0 16px; line-height:1.6; }");
            out.println("ul { padding-left:22px; line-height:1.8; }");
            out.println(".pass { color:var(--pass); font-weight:700; }");
            out.println(".fail { color:var(--fail); font-weight:700; }");
            out.println(".summary-grid {"
                    + "display:grid;"
                    + "grid-template-columns:repeat(auto-fit,minmax(180px,1fr));"
                    + "gap:12px;"
                    + "margin:20px 0;"
                    + "}");
            out.println(".summary-card {"
                    + "padding:14px 16px;"
                    + "border-radius:16px;"
                    + "border:1px solid #d7e0e5;"
                    + "background:#f8fafc;"
                    + "}");
            out.println(".summary-card strong { display:block; margin-bottom:6px; }");
            out.println(".meter {"
                    + "width:100%;"
                    + "height:14px;"
                    + "margin:12px 0 8px;"
                    + "border-radius:999px;"
                    + "overflow:hidden;"
                    + "background:#dbe5e3;"
                    + "}");
            out.println(".meter-fill {"
                    + "height:100%;"
                    + "width:" + progressPercentage + "%;"
                    + "border-radius:inherit;"
                    + "background:var(--" + strengthClass + ");"
                    + "}");
            out.println(".strength-box {"
                    + "margin-top:20px;"
                    + "padding:16px 18px;"
                    + "border-radius:16px;"
                    + "background:#f8fafc;"
                    + "border:1px solid #d7e0e5;"
                    + "}");
            out.println(".label { font-weight:700; font-size:1.1rem; }");
            out.println(".weak { color:var(--weak); }");
            out.println(".medium { color:var(--medium); }");
            out.println(".strong { color:var(--strong); }");
            out.println(".tips-box {"
                    + "margin-top:20px;"
                    + "padding:16px 18px;"
                    + "border-radius:16px;"
                    + "background:#fffaf0;"
                    + "border:1px solid #f1dcc0;"
                    + "}");
            out.println(".tips-box h2 { margin:0 0 10px; font-size:1.05rem; color:#134e4a; }");
            out.println(".actions { margin-top:24px; }");
            out.println(".actions a {"
                    + "display:inline-block;"
                    + "padding:12px 18px;"
                    + "border-radius:999px;"
                    + "background:#0f766e;"
                    + "color:#fff;"
                    + "text-decoration:none;"
                    + "font-weight:700;"
                    + "}");
            out.println("</style>");
            out.println("</head>");
            out.println("<body>");
            out.println("<main class=\"card\">");
            out.println("<h1>Password Strength Result</h1>");
            out.println("<p>Each password rule is checked below. The server decides the final result, so this is the authoritative strength check.</p>");
            out.println("<div class=\"summary-grid\">");
            out.println("<div class=\"summary-card\"><strong>Rules Passed</strong>" + passedRules + " out of 4</div>");
            out.println("<div class=\"summary-card\"><strong>Password Length</strong>" + password.length() + " characters</div>");
            out.println("<div class=\"summary-card\"><strong>Strength Level</strong><span class=\"" + strengthClass + "\">" + strength + "</span></div>");
            out.println("</div>");
            out.println("<ul>");
            out.println(buildRuleItem("Length is at least 8 characters", hasMinimumLength));
            out.println(buildRuleItem("Contains at least one uppercase letter", hasUppercase));
            out.println(buildRuleItem("Contains at least one digit", hasDigit));
            out.println(buildRuleItem("Contains at least one special character", hasSpecialCharacter));
            out.println("</ul>");
            out.println("<div class=\"strength-box\">");
            out.println("<div class=\"label\">Strength Meter</div>");
            out.println("<div class=\"meter\"><div class=\"meter-fill\"></div></div>");
            out.println("<div>Rules passed: <strong>" + passedRules + " / 4</strong></div>");
            out.println("<div class=\"label\">Overall Strength: <span class=\"" + strengthClass + "\">" + strength + "</span></div>");
            out.println("</div>");
            out.println("<div class=\"tips-box\">");
            out.println("<h2>How to Improve It</h2>");
            out.println("<ul>");
            for (String improvementTip : improvementTips) {
                out.println("<li>" + improvementTip + "</li>");
            }
            out.println("</ul>");
            out.println("</div>");
            out.println("<div class=\"actions\">");
            out.println("<a href=\"" + request.getContextPath() + "/index.html\">Check Another Password</a>");
            out.println("</div>");
            out.println("</main>");
            out.println("</body>");
            out.println("</html>");
        }
    }

    /**
     * Counts the number of validation rules that passed.
     */
    private int countPassedRules(boolean... ruleResults) {
        int count = 0;
        for (boolean ruleResult : ruleResults) {
            if (ruleResult) {
                count++;
            }
        }
        return count;
    }

    /**
     * Maps the passed rule count to the requested strength label.
     */
    private String determineStrength(int passedRules) {
        if (passedRules == 4) {
            return "Strong";
        }
        if (passedRules == 3) {
            return "Medium";
        }
        return "Weak";
    }

    /**
     * Returns the CSS class used to color the strength label.
     */
    private String determineStrengthClass(String strength) {
        if ("Strong".equals(strength)) {
            return "strong";
        }
        if ("Medium".equals(strength)) {
            return "medium";
        }
        return "weak";
    }

    /**
     * Builds improvement suggestions based on the failed rules.
     */
    private List<String> buildImprovementTips(
            boolean hasMinimumLength,
            boolean hasUppercase,
            boolean hasDigit,
            boolean hasSpecialCharacter
    ) {
        List<String> tips = new ArrayList<>();

        if (!hasMinimumLength) {
            tips.add("Increase the password length to at least 8 characters.");
        }
        if (!hasUppercase) {
            tips.add("Add at least one uppercase letter such as A or Z.");
        }
        if (!hasDigit) {
            tips.add("Include at least one digit such as 7 or 9.");
        }
        if (!hasSpecialCharacter) {
            tips.add("Include at least one special character such as @, #, or !.");
        }
        if (tips.isEmpty()) {
            tips.add("Great job. This password satisfies all four rules.");
            tips.add("For even better security, avoid reusing it on other websites.");
        }

        return tips;
    }

    /**
     * Builds a list item showing Pass or Fail for a rule.
     */
    private String buildRuleItem(String ruleDescription, boolean passed) {
        String status = passed ? "Pass" : "Fail";
        String cssClass = passed ? "pass" : "fail";
        return "<li>" + ruleDescription + ": <span class=\"" + cssClass + "\">" + status + "</span></li>";
    }
}
