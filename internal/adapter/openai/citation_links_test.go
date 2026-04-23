package openai

import "testing"

func TestReplaceCitationMarkersWithLinks(t *testing.T) {
	raw := "这是一条更新[citation:1]，更多信息见[citation:2]。"
	links := map[int]string{
		1: "https://example.com/news-1",
		2: "https://example.com/news-2",
	}

	got := replaceCitationMarkersWithLinks(raw, links)
	want := "这是一条更新[1](https://example.com/news-1)，更多信息见[2](https://example.com/news-2)。"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestReplaceCitationMarkersWithLinksKeepsUnknownIndex(t *testing.T) {
	raw := "只有一个来源[citation:1]，未知来源[citation:3]。"
	links := map[int]string{1: "https://example.com/a"}

	got := replaceCitationMarkersWithLinks(raw, links)
	want := "只有一个来源[1](https://example.com/a)，未知来源[citation:3]。"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
