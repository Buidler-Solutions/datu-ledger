import Background from './components/Background';
import Nav from './components/Nav';
import { useProgress } from './lib/lessons';
import { useRoute } from './router';
import Home from './pages/Home';
import Lab from './pages/Lab';
import Lesson1 from './pages/lessons/Lesson1';
import Lesson2 from './pages/lessons/Lesson2';
import Lesson3 from './pages/lessons/Lesson3';
import Lesson4 from './pages/lessons/Lesson4';
import Lesson5 from './pages/lessons/Lesson5';
import Lesson6 from './pages/lessons/Lesson6';
import Lesson7 from './pages/lessons/Lesson7';
import Lesson8 from './pages/lessons/Lesson8';

const PAGES = {
  1: Lesson1,
  2: Lesson2,
  3: Lesson3,
  4: Lesson4,
  5: Lesson5,
  6: Lesson6,
  7: Lesson7,
  8: Lesson8,
};

export default function App() {
  const route = useRoute();
  const { done, mark } = useProgress();

  let content;
  if (route.page === 'lab') content = <Lab />;
  else if (route.page === 'lesson' && PAGES[route.lesson]) {
    const Lesson = PAGES[route.lesson];
    content = <Lesson mark={mark} done={done.has(route.lesson)} />;
  } else content = <Home progress={done} />;

  return (
    <>
      <Background />
      <div className="shell">
        <Nav route={route} progress={done} />
        <main className="main">{content}</main>
      </div>
    </>
  );
}
