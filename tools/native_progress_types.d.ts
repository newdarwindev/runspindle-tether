/** Structural surface used by the synthetic native-zoom driver, not a runtime adapter. */
export interface Metrics {
  cssZoom: string;
  visualViewportScale: number;
  outerWidth: number;
  innerWidth: number;
  dpr: number;
}
export interface Pixels {
  size: number[];
  color_count_lower_bound: number;
  rgb_sha256?: string;
}
export interface Locator {
  evaluate<T>(fn: (element: HTMLElement) => T): Promise<T>;
  innerText(): Promise<string>;
  getAttribute(name: string): Promise<string | null>;
  count(): Promise<number>;
  getByRole(role: string, options: { name: string; exact: boolean }): Locator;
  getByLabel(label: string, options: { exact: boolean }): Locator;
}
export interface Page {
  locator(selector: string): Locator;
  evaluate<T>(fn: () => T): Promise<Awaited<T>>;
  keyboard: { press(key: string): Promise<void> };
  content(): Promise<string>;
  setDefaultTimeout(ms: number): void;
  goto(url: string): Promise<unknown>;
  addStyleTag(options: { content: string }): Promise<Locator>;
}
export interface Session {
  send(
    method: "Page.getLayoutMetrics",
  ): Promise<{
    visualViewport: { zoom: number };
    contentSize: { width: number; height: number };
    layoutViewport: { clientWidth: number; clientHeight: number };
  }>;
  send(
    method: "Page.captureScreenshot",
    options: {
      format: string;
      fromSurface: boolean;
      captureBeyondViewport: boolean;
      clip?: {
        x: number;
        y: number;
        width: number;
        height: number;
        scale: number;
      };
    },
  ): Promise<{ data: string }>;
}
export interface BrowserContext {
  close(): Promise<void>;
  route(
    pattern: string,
    handler: (route: {
      request(): { url(): string };
      continue(): Promise<void>;
      abort(): Promise<void>;
    }) => Promise<void>,
  ): Promise<void>;
  pages(): Page[];
  newPage(): Promise<Page>;
  newCDPSession(page: Page): Promise<Session>;
  browser(): { version(): string } | null;
}
export interface BrowserModule {
  chromium: {
    launchPersistentContext(
      profile: string,
      options: {
        executablePath: string;
        chromiumSandbox: boolean;
        headless: boolean;
        viewport: null;
        locale: string;
        timezoneId: string;
        colorScheme: string;
        reducedMotion: string;
        offline: boolean;
        timeout: number;
        args: string[];
      },
    ): Promise<BrowserContext>;
  };
}
export interface Mapping {
  scenarios: {
    id: string;
    expected_visible: string[];
    accessible_heading: string;
    plain_text_label: string;
  }[];
}
export interface Scenarios {
  scenarios: { title: string; artifact?: unknown }[];
}
export interface Options {
  browser: string;
  playwright: string;
  output: string;
}
