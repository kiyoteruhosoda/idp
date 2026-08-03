import React, { StrictMode, useEffect, useReducer } from 'react';
import { createRoot } from 'react-dom/client';

type FieldMap = Record<string, string>;

type SurfaceState = {
  dirty: boolean;
  submitting: boolean;
  lastField: string;
  fields: FieldMap;
};

type SurfaceAction =
  | { type: 'fieldChanged'; name: string; value: string }
  | { type: 'formSubmitting' }
  | { type: 'reset' };

interface SurfaceStrategy {
  readonly componentName: string;
  initialState(surface: HTMLElement): SurfaceState;
  reduce(state: SurfaceState, action: SurfaceAction): SurfaceState;
  render(state: SurfaceState): React.ReactElement | null;
}

const baseInitialState = (surface: HTMLElement): SurfaceState => {
  const fields: FieldMap = {};
  surface.querySelectorAll<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>('input[name], textarea[name], select[name]').forEach((field) => {
    if (field instanceof HTMLInputElement && field.type === 'password') return;
    fields[field.name] = field.value;
  });
  return { dirty: false, submitting: false, lastField: '', fields };
};

abstract class FormSurfaceStrategy implements SurfaceStrategy {
  abstract readonly componentName: string;

  initialState(surface: HTMLElement): SurfaceState {
    return baseInitialState(surface);
  }

  reduce(state: SurfaceState, action: SurfaceAction): SurfaceState {
    switch (action.type) {
      case 'fieldChanged':
        return {
          ...state,
          dirty: true,
          lastField: action.name,
          fields: { ...state.fields, [action.name]: action.value },
        };
      case 'formSubmitting':
        return { ...state, submitting: true };
      case 'reset':
        return { dirty: false, submitting: false, lastField: '', fields: {} };
      default:
        return state;
    }
  }

  // 汎用フォーム（ログイン画面等）では可視ステータスを描画しない。フォーム状態は
  // hydration 用の data-* 属性として引き続き保持する（SurfaceApp の useEffect を参照）。
  render(_state: SurfaceState): React.ReactElement | null {
    return null;
  }
}

class GenericPageStrategy extends FormSurfaceStrategy {
  readonly componentName = 'GenericPageSurface';
}

// 画面固有の描画を持つ surface だけをここに登録する。未登録の `data-react-surface`
// は GenericPageStrategy（可視要素を描画せず、フォーム状態を data-* に反映するだけ）
// になる。文言を描画する strategy を追加する場合は、テンプレートと同じ翻訳
// （`messages.get`）を使う経路を用意し、ここに日本語を直書きしない。
const strategies: Record<string, SurfaceStrategy> = {};

const strategyFor = (surface: HTMLElement): SurfaceStrategy => {
  const name = surface.dataset.reactSurface ?? '';
  return strategies[name] ?? new GenericPageStrategy();
};

const SurfaceApp = ({ surface, strategy }: { surface: HTMLElement; strategy: SurfaceStrategy }) => {
  const [state, dispatch] = useReducer(strategy.reduce.bind(strategy), surface, strategy.initialState.bind(strategy));

  useEffect(() => {
    const onInput = (event: Event) => {
      const target = event.target as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null;
      if (!target?.name) return;
      dispatch({ type: 'fieldChanged', name: target.name, value: target.value });
    };
    const onSubmit = () => dispatch({ type: 'formSubmitting' });
    surface.addEventListener('input', onInput);
    surface.addEventListener('submit', onSubmit);
    return () => {
      surface.removeEventListener('input', onInput);
      surface.removeEventListener('submit', onSubmit);
    };
  }, [surface]);

  useEffect(() => {
    surface.dataset.reactHydrated = 'true';
    surface.dataset.reactDirty = state.dirty ? 'true' : 'false';
    surface.dataset.reactSubmitting = state.submitting ? 'true' : 'false';
    surface.dataset.reactLastField = state.lastField;
  }, [surface, state]);

  return strategy.render(state);
};

const mountSurface = (surface: HTMLElement) => {
  if (surface.dataset.reactMounted === 'true') return;
  const mount = document.createElement('div');
  mount.className = 'react-island';
  mount.dataset.reactIslandFor = surface.dataset.reactSurface ?? 'GenericPageSurface';
  surface.appendChild(mount);
  surface.dataset.reactMounted = 'true';
  const strategy = strategyFor(surface);
  createRoot(mount).render(
    <StrictMode>
      <SurfaceApp surface={surface} strategy={strategy} />
    </StrictMode>,
  );
};

const hydrateAll = () => {
  const declared = Array.from(document.querySelectorAll<HTMLElement>('[data-react-surface]'));
  document.body.dataset.reactSurface ||= declared[0]?.dataset.reactSurface ?? 'GenericPageSurface';
  document.body.dataset.reactMode = 'react';
  // 描画先はテンプレートが宣言した領域だけにする。document.body を描画先にすると
  // island が </footer> の後ろ（レイアウトの外）へ差し込まれるため、宣言が無い画面
  // でのみ body をフォーム状態の観測対象として使う。
  const surfaces = declared.length > 0 ? declared : [document.body];
  surfaces.forEach(mountSurface);
};

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', hydrateAll);
} else {
  hydrateAll();
}
