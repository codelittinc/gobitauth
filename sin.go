package bitauth

type SIN string

type SINInfo struct {
	SIN        SIN
	PublicKey  string
	PrivateKey string
}

func GetSINFromPublicKey(key string) (SIN, error) {
	return SIN(""), nil
}

func GenerateSIN() (SINInfo, error) {
	return SINInfo{}, nil
}

func GetPublicKeyFromPrivateKey(private string) (string, error) {
	return "", nil
}
