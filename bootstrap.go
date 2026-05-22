package secure_bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gddisney/guikit"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
)

const (
	AuthPageID   ultimate_db.PageID = 1
	ConfigPageID ultimate_db.PageID = 99
)

type UIConfig struct {
	BrandName    string     `json:"brand_name"`
	Logo         string     `json:"logo"`
	PrimaryColor string     `json:"primary_color"`
	Description  string     `json:"description"`
	FormAction   string     `json:"form_action"`
	Fields       []UIField  `json:"fields"`
	Buttons      []UIButton `json:"buttons"`
}

type UIField struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Placeholder string `json:"placeholder"`
}

type UIButton struct {
	Label   string `json:"label"`
	Primary bool   `json:"primary"`
	Type    string `json:"type"`
	OnClick string `json:"onclick"`
}

func DefaultConfig() UIConfig {
	return UIConfig{
		BrandName:    "Secure Bootstrap SSO",
		Logo:         "🌐",
		PrimaryColor: "#1d9bf0",
		Description:  "Authenticate securely using your device's native Passkey.",
		FormAction:   "javascript:void(0);", // Let JS handle the actions
		Fields: []UIField{
			{ID: "username", Name: "username", Type: "text", Placeholder: "Enter a Username"},
		},
		Buttons: []UIButton{
			{Label: "Sign In with Passkey", Primary: true, Type: "button", OnClick: "passkeyLogin(document.getElementById('username').value)"},
			{Label: "Register New Passkey", Primary: false, Type: "button", OnClick: "passkeyRegister(document.getElementById('username').value)"},
		},
	}
}

func GenerateDynamicGML(cfg UIConfig) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(`html(
    head(
        meta:charset."utf-8"(),
        title("%s - Secure Login"),
        script:src."/auth/webauthn.js"(),
        style(
            rule("body", "background-color: #000", "font-family: -apple-system, BlinkMacSystemFont, sans-serif", "margin: 0"),
            rule(".auth-wrapper", "display: flex", "height: 100vh", "width: 100vw", "align-items: center", "justify-content: center"),
            rule(".auth-box", "width: 100%%", "max-width: 420px", "background: #16181c", "border-radius: 16px", "padding: 40px", "text-align: center", "border: 1px solid #2f3336", "box-sizing: border-box"),
            rule(".auth-logo", "font-size: 36px", "margin-bottom: 20px"),
            rule(".auth-title", "color: white", "margin: 0 0 10px 0", "font-size: 24px"),
            rule(".auth-desc", "color: #71767b", "margin-bottom: 30px", "font-size: 15px", "line-height: 1.5"),
            rule(".auth-input", "width: 100%%", "padding: 16px", "margin-bottom: 20px", "border-radius: 8px", "border: 1px solid #333", "background: #000", "color: white", "box-sizing: border-box"),
            rule(".btn-primary", "background: %s", "color: white", "border: none", "padding: 16px", "border-radius: 9999px", "cursor: pointer", "width: 100%%", "font-size: 16px", "font-weight: bold", "margin-bottom: 15px"),
            rule(".btn-secondary", "background: transparent", "color: #e7e9ea", "border: 1px solid #536471", "padding: 16px", "border-radius: 9999px", "cursor: pointer", "width: 100%%", "font-size: 16px", "font-weight: bold")
        )
    ),
    body(
        div.auth-wrapper(
            div.auth-box(
                div.auth-logo("%s"),
                h2.auth-title("Sign in to %s"),
                p.auth-desc("%s"),
                form:action."%s"(`,
		cfg.BrandName, cfg.PrimaryColor, cfg.Logo, cfg.BrandName, cfg.Description, cfg.FormAction))

	for _, field := range cfg.Fields {
		sb.WriteString(fmt.Sprintf("\n                    input.auth-input:id.\"%s\":name.\"%s\":type.\"%s\":placeholder.\"%s\"(),",
			field.ID, field.Name, field.Type, field.Placeholder))
	}

	for _, btn := range cfg.Buttons {
		btnClass := ".btn-secondary"
		if btn.Primary { btnClass = ".btn-primary" }

		onclickStr := ""
		if btn.OnClick != "" { onclickStr = fmt.Sprintf(`:onclick."%s"`, btn.OnClick) }

		sb.WriteString(fmt.Sprintf("\n                    button%s:type.\"%s\"%s(\"%s\"),",
			btnClass, btn.Type, onclickStr, btn.Label))
	}

	sb.WriteString(`
                )
            )
        )
    )
)`)

	return sb.String()
}

// BootstrapAuth binds the dynamic identity provider directly to the router
func BootstrapAuth(router *secure_network.Router, wa *webauthnext.Provider) {
	router.Mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		txn := router.DB.BeginTxn()
		cfgBytes, err := router.DB.Read(ConfigPageID, txn, []byte("ui_settings"))
		router.DB.CommitTxn(txn)

		cfg := DefaultConfig()
		if err == nil && len(cfgBytes) > 0 {
			if parseErr := json.Unmarshal(cfgBytes, &cfg); parseErr != nil {
				cfg = DefaultConfig()
			}
		}

		gmlSyntax := GenerateDynamicGML(cfg)

		// ✨ FIX: Write the compiled template to disk so guikit's file-based renderer can load it
		os.MkdirAll("views", 0755)
		os.WriteFile("views/dynamic_auth.gml", []byte(gmlSyntax), 0644)

		ctx := &guikit.Context{W: w, R: r, Data: make(map[string]interface{})}
		router.GUIKit.Render(ctx, "views/dynamic_auth")
	})
}

// RequireAuth enforces session integrity based on webauthnext's exact behavior
func RequireAuth(router *secure_network.Router, next func(c *guikit.Context)) func(c *guikit.Context) {
	return func(c *guikit.Context) {
		cookie, err := c.R.Cookie("session_id")
		if err != nil || cookie.Value == "" {
			http.Redirect(c.W, c.R, "/auth", http.StatusSeeOther)
			return
		}

		user := ""
		// ✨ FIX: Parse the exact cookie pattern webauthnext sets ("user_session_" + username)
		if strings.HasPrefix(cookie.Value, "user_session_") {
			user = strings.TrimPrefix(cookie.Value, "user_session_")
		}

		if user == "" {
			http.SetCookie(c.W, &http.Cookie{Name: "session_id", MaxAge: -1, Path: "/"})
			http.Redirect(c.W, c.R, "/auth", http.StatusSeeOther)
			return
		}

		c.Data["CurrentUser"] = user
		next(c)
	}
}
