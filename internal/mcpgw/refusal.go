package mcpgw

// refuseText answers a refusal in the appropriate MCP result shape.
func (rc *request) refuseText(tool bool, msg, reason, provider string) int64 {
	if tool {
		return rc.reply(map[string]any{"content": []map[string]any{{"type": "text", "text": msg}}, "isError": true})
	}
	data := map[string]any{"reason": reason}
	if provider != "" {
		data["provider"] = provider
	}
	return rc.failData(codeDenied, msg, data)
}
