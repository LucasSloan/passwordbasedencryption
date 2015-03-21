package passwordbasedencryption

import "testing"

func TestBasicDecryption(t *testing.T) {
	cases := []struct {
		ciphertext, password, plaintext string
	}{
		{"u6ccN+pf88NQFo0p2W5HUgoJXW/iGZPt", "password", "plaintext"},
		{"nWUp2auqbcKucN6VBYkL8sQtYwyFc6dXjLLJjOhR4WTKS1XfMdmx0kkYBiD4sVDycSH1Vp5JDXqDLg74PSBQ8j5k5Ongvel2", "password", "Lorem ipsum dolor sit amet, consectetur adipiscing elit."},
		{"TgLG/fANuEVycFMO6Ap7eA==", "password", ""},
		{"Wt9vfiouLnMHPEcSBx2ZUYpVYcSrmR9O1IAt7768VbK1DH5tZe3A2YNyqdHA0dLma3Hlwe3WeU4Ba32+RLG5dIH7KUrLlZH9", "password", "ðƏ kwɪk braʊn fƊks dʒʊmptƏʊvƏ ðƏ lɛɪzi: dƊgz"},
		{"inZQMiY+UsI5HLLifuvV2HxBhoj3nNNA", "g9Q95=yNVt7E?a+nDN=%", "plaintext"},
		{"1uurVxPzTV5KGuL1ZupT+e+K57KhfDdGjV/Ej+zWvZrajf5B/KfyoGBSiE3qSYX5iIZoPO/XIIFplaAtPwAI1eWsWx4NFHWM", "g9Q95=yNVt7E?a+nDN=%", "Lorem ipsum dolor sit amet, consectetur adipiscing elit."},
		{"ygsi6PB2b6RcOIJeiFAcIg==", "g9Q95=yNVt7E?a+nDN=%", ""},
		{"4v7gZN8/e20qX7Nm5EVbRs84zZ7IkWt+GNi8q+4dETeJodVONdoF7jaXBl8qialZ5KIlvlDD04idlAVjqiY6H/HDxkWBcyTE", "g9Q95=yNVt7E?a+nDN=%", "ðƏ kwɪk braʊn fƊks dʒʊmptƏʊvƏ ðƏ lɛɪzi: dƊgz"},
	}
	for _, c := range cases {
		got, err := DecryptString(c.password, 1000, c.ciphertext)
		if err != nil {
			t.Errorf("Got error %q for password %q, ciphertext %q", err.Error(), c.password, c.ciphertext)
		}
		if got != c.plaintext {
			t.Errorf("DecryptString(%q, 1000, %q) == %q, want %q", c.password, c.ciphertext, got, c.plaintext)
		}
	}
}
