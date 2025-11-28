package base64

func Base64Encode(data []byte) string {
	var buf bytes.Buffer
	enc := base64.NewEncoder(base64.StdEncoding, &buf)
	_, err := enc.Write(data)
	if err != nil {
		return ""
	}
	if enc.Close() != nil {
		return ""
	}
	return buf.String()
}

func Base64Decode(data string) ([]byte, error) {
	decodedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return decodedData, nil
}