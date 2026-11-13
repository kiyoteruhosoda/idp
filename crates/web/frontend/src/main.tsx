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

  // Generic forms (login screen etc.) render no visible status. Form state is
  // still kept in data-* attributes for hydration (see SurfaceApp's useEffect).
  render(_state: SurfaceState): React.ReactElement | null {
    return null;
  }
}

class GenericPageStrategy extends FormSurfaceStrategy {
  readonly componentName = 'GenericPageSurface';
}

// Register here only surfaces with screen-specific rendering. An unregistered `data-react-surface`
// becomes GenericPageStrategy (renders no visible elements, only reflects form state into data-*).
// When adding a strategy that renders wording, provide a path using the same translations as templates
// (`messages.get`), and do not hard-code Japanese here.
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
  // Render only into the region the template declared. Rendering into document.body would
  // insert the island after </footer> (outside the layout), so body is used as the form-state
  // observation target only on screens without a declaration.
  const surfaces = declared.length > 0 ? declared : [document.body];
  surfaces.forEach(mountSurface);
};

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', hydrateAll);
} else {
  hydrateAll();
}
